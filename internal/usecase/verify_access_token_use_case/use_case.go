package verifyaccesstokenusecase

import (
	"context"
	"errors"
	"goauth/internal/auth"
	"goauth/internal/failure"
	"goauth/internal/logger"
	"goauth/internal/store"
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
	Token string
}

type VerifyTokenResponse struct {
	Valid       bool
	UserID      pgtype.UUID
	Email       string
	Permissions int64
	ExpiresAt   time.Time
}

type VerifyAccessTokenUseCase struct {
	ctx context.Context

	*Params
	*Payload
}

func New(ctx context.Context, params *Params, payload *Payload) *VerifyAccessTokenUseCase {
	return &VerifyAccessTokenUseCase{ctx: ctx, Params: params, Payload: payload}
}

func (u *VerifyAccessTokenUseCase) Execute() (*VerifyTokenResponse, error) {
	tokenString := u.Token

	claims, err := auth.ValidateAccessToken(tokenString)
	if err != nil {
		if errors.Is(err, auth.ErrExpiredToken) {
			return nil, failure.ErrTokenExpired
		}
		return nil, failure.ErrInvalidToken
	}

	id, err := uuid.Parse(claims.UserID)
	userID := pgtype.UUID{Bytes: [16]byte(id), Valid: true}
	if err != nil {
		logger.Warn().
			Str("user_id", claims.UserID).
			Err(err).
			Msg("invalid user_id in token claims")
		return nil, failure.ErrInvalidToken
	}

	// check if token is blacklisted in redis (for logout)
	blacklistKey := "blacklist:access:" + tokenString
	exists, err := u.Redis.Exists(u.ctx, blacklistKey).Result()
	if err != nil {
		logger.Warn().
			Err(err).
			Msg("redis error checking token blacklist")
		return nil, failure.ErrDatabaseError
	} else if exists > 0 {
		return nil, failure.ErrTokenRevoked
	}

	user, err := getuserbyidusecase.New(u.ctx, &getuserbyidusecase.Params{
		Store: u.Store,
		Redis: u.Redis,
	}, &getuserbyidusecase.Payload{
		UserID: userID,
	}).Execute()

	if err != nil {
		return nil, err
	}

	if !user.IsActive.Bool {
		return nil, failure.ErrUserInactive
	}

	return &VerifyTokenResponse{
		Valid:       true,
		UserID:      user.ID,
		Email:       user.Email,
		Permissions: user.Permissions,
		ExpiresAt:   claims.ExpiresAt.Time,
	}, nil
}
