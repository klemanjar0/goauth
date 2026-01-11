package verifyemailusecase

import (
	"context"
	"database/sql"
	"errors"
	"goauth/internal/auth"
	"goauth/internal/failure"
	"goauth/internal/logger"
	"goauth/internal/store"
	"goauth/internal/store/pg/repository"
	createauditlogusecase "goauth/internal/usecase/create_audit_log_use_case"
	invalidateusercacheusecase "goauth/internal/usecase/invalidate_user_cache_use_case"

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

type VerifyEmailUseCase struct {
	ctx context.Context

	*Params
	*Payload
}

func New(ctx context.Context, params *Params, payload *Payload) *VerifyEmailUseCase {
	return &VerifyEmailUseCase{ctx: ctx, Params: params, Payload: payload}
}

func (u *VerifyEmailUseCase) Execute() error {
	if u.Token == "" {
		return failure.ErrInvalidToken
	}

	tokenHash := auth.HashToken256(u.Token)
	verificationToken, err := u.Store.Queries.GetEmailVerificationTokenByHash(u.ctx, tokenHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.Warn().
				Str("token", u.Token).
				Msg("email verification token not found or expired")
			return failure.ErrInvalidToken
		}
		logger.Error().
			Err(err).
			Msg("database error while fetching email verification token")
		return failure.ErrDatabaseError
	}

	err = u.Store.ExecTx(u.ctx, func(tx *repository.Queries) error {
		if err := tx.MarkEmailVerificationTokenUsed(u.ctx, verificationToken.ID); err != nil {
			logger.Error().
				Err(err).
				Str("token_id", verificationToken.ID.String()).
				Msg("failed to mark email verification token as used")
			return failure.ErrDatabaseError
		}

		_, updateErr := tx.UpdateUser(u.ctx, repository.UpdateUserParams{
			ID:             verificationToken.UserID,
			EmailConfirmed: pgtype.Bool{Bool: true, Valid: true},
		})
		if updateErr != nil {
			logger.Error().
				Err(updateErr).
				Str("user_id", verificationToken.UserID.String()).
				Msg("failed to update user email_confirmed status")
			return failure.ErrDatabaseError
		}

		return nil
	})

	if err != nil {
		logger.Error().
			Err(err).
			Str("user_id", verificationToken.UserID.String()).
			Msg("email verification transaction failed")
		return failure.ErrDatabaseError
	}

	if err := invalidateusercacheusecase.New(u.ctx,
		&invalidateusercacheusecase.Params{Redis: u.Redis},
		&invalidateusercacheusecase.Payload{UserID: verificationToken.UserID},
	).Execute(); err != nil {
		return err
	}

	err = createauditlogusecase.New(
		u.ctx,
		&createauditlogusecase.Params{
			Store: u.Store,
		},
		&createauditlogusecase.Payload{
			UserID:    verificationToken.UserID,
			EventType: "email_verified",
			Ip:        "",
			UserAgent: "",
			Payload: map[string]any{
				"token_id": verificationToken.ID.String(),
			},
		}).
		Execute()

	if err != nil {
		logger.Warn().
			Err(err).
			Str("user_id", verificationToken.UserID.String()).
			Msg("failed to create audit log for email verification")
	}

	logger.Info().
		Str("user_id", verificationToken.UserID.String()).
		Msg("email verified successfully")

	return nil
}
