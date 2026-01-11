package sendverificationemailusecase

import (
	"context"
	"goauth/internal/auth"
	"goauth/internal/kafka"
	"goauth/internal/logger"
	"goauth/internal/store"
	"goauth/internal/store/pg/repository"
	enqueueverificationemailusecase "goauth/internal/usecase/enqueue_verification_email_use_case"
	registerusecase "goauth/internal/usecase/register_use_case"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type Params struct {
	Store    *store.Store
	Producer *kafka.Producer
}

type Payload struct {
	User *registerusecase.Response
}

type SendVerificationEmailUseCase struct {
	ctx context.Context

	*Params
	*Payload
}

func New(ctx context.Context, params *Params, payload *Payload) *SendVerificationEmailUseCase {
	return &SendVerificationEmailUseCase{ctx: ctx, Params: params, Payload: payload}
}

func (u *SendVerificationEmailUseCase) Execute() error {
	token := uuid.New().String()
	params := repository.CreateEmailVerificationTokenParams{
		UserID:    u.User.UserID,
		TokenHash: auth.HashToken256(token),
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(24 * time.Hour), Valid: true},
	}

	_, err := u.Store.Queries.CreateEmailVerificationToken(u.ctx, params)
	if err != nil {
		logger.Error().
			Str("email", u.User.Email).
			Err(err).
			Msg("failed to create email verification token")
		return err
	}

	if err := enqueueverificationemailusecase.New(
		u.ctx,
		&enqueueverificationemailusecase.Params{
			Producer: u.Producer,
		},
		&enqueueverificationemailusecase.Payload{
			To:    u.User.Email,
			Token: token,
		},
	).Execute(); err != nil {
		logger.Error().
			Err(err).
			Str("email", u.User.Email).
			Msg("failed to enqueue verification email")
		return err
	}

	logger.Info().
		Str("email", u.User.Email).
		Str("user_id", u.User.UserID.String()).
		Msg("verification email queued")

	return nil
}
