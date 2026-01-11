package refreshaccesstokenusecase

import (
	"context"
	"database/sql"
	"errors"
	"goauth/internal/auth"
	"goauth/internal/failure"
	"goauth/internal/logger"
	"goauth/internal/store"
	"goauth/internal/store/pg/repository"
	getuserbyidusecase "goauth/internal/usecase/get_user_by_id_use_case"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/redis/go-redis/v9"
)

type Params struct {
	Store *store.Store
	Redis *redis.Client
}

type Payload struct {
	RefreshToken string
	DeviceInfo   string
}

type Response struct {
	AccessToken      string
	RefreshToken     string
	RefreshTokenID   pgtype.UUID
	AccessExpiresIn  int64 // seconds until access token expires
	RefreshExpiresIn int64 // seconds until refresh token expires
}

type RefreshAccessTokenUseCase struct {
	ctx context.Context

	*Params
	*Payload
}

func New(ctx context.Context, params *Params, payload *Payload) *RefreshAccessTokenUseCase {
	return &RefreshAccessTokenUseCase{ctx: ctx, Params: params, Payload: payload}
}

func (u *RefreshAccessTokenUseCase) Execute() (*Response, error) {
	refreshTokenIDStr, err := auth.ValidateRefreshToken(u.RefreshToken)
	if err != nil {
		if errors.Is(err, auth.ErrExpiredToken) {
			return nil, failure.ErrTokenExpired
		}
		return nil, failure.ErrInvalidToken
	}

	// parse the token id from jwt subject
	refreshTokenUUID, err := uuid.Parse(refreshTokenIDStr)
	refreshTokenID := pgtype.UUID{Bytes: [16]byte(refreshTokenUUID), Valid: true}
	if err != nil {
		logger.Warn().
			Str("token_id", refreshTokenIDStr).
			Err(err).
			Msg("invalid token_id in refresh token")
		return nil, failure.ErrInvalidToken
	}

	dbToken, err := u.Store.Queries.GetRefreshToken(u.ctx, refreshTokenID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.Warn().
				Str("token_id", refreshTokenID.String()).
				Msg("refresh token not found or expired")
			return nil, failure.ErrInvalidToken
		}
		logger.Error().
			Err(err).
			Str("token_id", refreshTokenID.String()).
			Msg("database error while fetching refresh token")
		return nil, failure.ErrDatabaseError
	}

	user, err := getuserbyidusecase.
		New(u.ctx,
			&getuserbyidusecase.Params{Store: u.Store, Redis: u.Redis},
			&getuserbyidusecase.Payload{UserID: dbToken.UserID},
		).
		Execute()

	if err != nil {
		return nil, err
	}

	if !user.IsActive.Bool {
		return nil, failure.ErrUserInactive
	}

	var accessToken, newRefreshToken string
	var newDBToken repository.RefreshToken
	var accessExpiresIn, refreshExpiresIn int64

	err = u.Store.ExecTx(u.ctx, func(tx *repository.Queries) error {
		dbToken, err := tx.GetRefreshTokenForUpdate(u.ctx, refreshTokenID)
		if err != nil {
			return err
		}

		if dbToken.LastUsedAt.Valid {
			logger.Warn().Msg("refresh token reuse detected")
			_ = tx.RevokeTokenFamily(u.ctx, refreshTokenID)
			return failure.ErrTokenRevoked
		}

		if err := tx.UpdateRefreshTokenLastUsed(u.ctx, refreshTokenID); err != nil {
			return err
		}

		accessToken, err = auth.GenerateAccessToken(dbToken.UserID.String())
		if err != nil {
			return err
		}

		refreshTokenExpiry := time.Now().Add(7 * 24 * time.Hour)
		newDBToken, err = tx.CreateRefreshToken(u.ctx, repository.CreateRefreshTokenParams{
			UserID:      dbToken.UserID,
			DeviceInfo:  pgtype.Text{String: u.DeviceInfo, Valid: u.DeviceInfo != ""},
			ExpiresAt:   pgtype.Timestamptz{Time: refreshTokenExpiry, Valid: true},
			RotatedFrom: refreshTokenID,
		})
		if err != nil {
			return err
		}

		newRefreshToken, err = auth.GenerateRefreshToken(newDBToken.ID.String())
		if err != nil {
			return err
		}

		accessClaims, _ := auth.ValidateAccessToken(accessToken)
		accessExpiresIn = int64(time.Until(accessClaims.ExpiresAt.Time).Seconds())
		refreshExpiresIn = int64(time.Until(refreshTokenExpiry).Seconds())

		return nil
	})

	if err != nil {
		return nil, err
	}

	logger.Info().
		Str("user_id", user.ID.String()).
		Str("old_token_id", refreshTokenID.String()).
		Str("new_token_id", newDBToken.ID.String()).
		Msg("tokens refreshed successfully with rotation")

	return &Response{
		AccessToken:      accessToken,
		RefreshToken:     newRefreshToken,
		RefreshTokenID:   newDBToken.ID,
		AccessExpiresIn:  accessExpiresIn,
		RefreshExpiresIn: refreshExpiresIn,
	}, nil
}
