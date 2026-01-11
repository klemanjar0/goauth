package handleemailmessageusecase

import (
	"context"
	"encoding/json"
	"goauth/internal/email"
	"goauth/internal/kafka"
	"goauth/internal/logger"
)

type Params struct {
}

type Payload struct {
	Key, Value []byte
}

type HandleEmailMessageUseCase struct {
	ctx context.Context

	*Params
	*Payload
}

func New(ctx context.Context, params *Params, payload *Payload) *HandleEmailMessageUseCase {
	return &HandleEmailMessageUseCase{ctx: ctx, Params: params, Payload: payload}
}

func (u *HandleEmailMessageUseCase) Execute() error {
	var job kafka.EmailJob
	if err := json.Unmarshal(u.Value, &job); err != nil {
		logger.Error().Err(err).Msg("failed to unmarshal email job")
		return err
	}

	logger.Info().
		Any("type", job.Type).
		Str("to", job.To).
		Msg("processing email job")

	var err error
	switch job.Type {
	case kafka.EmailJobVerification:
		err = email.SendVerificationEmail(job.To, job.Token)
	case kafka.EmailJobPasswordReset:
		err = email.SendPasswordResetEmail(job.To, job.Token)
	default:
		logger.Warn().Any("type", job.Type).Msg("unknown email type")
		return nil
	}

	if err != nil {
		logger.Error().
			Err(err).
			Any("type", job.Type).
			Str("to", job.To).
			Msg("failed to send email")
		return err
	}

	logger.Info().
		Any("type", job.Type).
		Str("to", job.To).
		Msg("email sent successfully")

	return nil
}
