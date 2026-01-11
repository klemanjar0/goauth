package sendpasswordresetemailusecase

import (
	"context"
	"goauth/internal/auth"
	"goauth/internal/kafka"
	"goauth/internal/logger"
	"goauth/internal/store"
	"goauth/internal/store/pg/repository"
	enqueuepasswordresetemailusecase "goauth/internal/usecase/enqueue_password_reset_email_use_case"
	getuserbyemailusecase "goauth/internal/usecase/get_user_by_email_use_case"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type Params struct {
	Store    *store.Store
	Producer *kafka.Producer
}

type Payload struct {
	Email string
}

type SendPasswordResetEmailUseCase struct {
	ctx context.Context

	*Params
	*Payload
}

func New(ctx context.Context, params *Params, payload *Payload) *SendPasswordResetEmailUseCase {
	return &SendPasswordResetEmailUseCase{ctx: ctx, Params: params, Payload: payload}
}

func (u *SendPasswordResetEmailUseCase) Execute() error {
	var user *repository.User
	var err error

	user, err = getuserbyemailusecase.New(
		u.ctx,
		&getuserbyemailusecase.Params{
			Store: u.Store,
		},
		&getuserbyemailusecase.Payload{
			Email: u.Email,
		},
	).Execute()

	if err != nil || user == nil {
		logger.Warn().Str("email", u.Email).Msg("password reset requested for non-existent email")
		return nil
	}

	if !user.IsActive.Bool {
		logger.Warn().Msg("user inactive")
		return nil
	}

	token := uuid.New().String()
	params := repository.CreatePasswordResetTokenParams{
		UserID:    user.ID,
		TokenHash: auth.HashToken256(token),
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(24 * time.Hour), Valid: true},
	}

	_, err = u.Store.Queries.CreatePasswordResetToken(u.ctx, params)

	if err != nil {
		logger.Error().
			Str("email", user.Email).
			Err(err).
			Msg("failed to create password reset token on db")
		return err
	}

	if err := enqueuepasswordresetemailusecase.New(
		u.ctx,
		&enqueuepasswordresetemailusecase.Params{
			Producer: u.Producer,
		},
		&enqueuepasswordresetemailusecase.Payload{
			To:    user.Email,
			Token: token,
		},
	).Execute(); err != nil {
		logger.Error().
			Err(err).
			Str("email", user.Email).
			Msg("failed to enqueue password reset email")
		return err
	}

	logger.Info().
		Str("email", user.Email).
		Msg("password reset email queued")

	return nil
}
