package enqueuepasswordresetemailusecase

import (
	"context"
	"goauth/internal/kafka"
)

type Params struct {
	Producer *kafka.Producer
}

type Payload struct {
	To, Token string
}

type EnqueuePasswordResetEmailUseCase struct {
	ctx context.Context

	*Params
	*Payload
}

func New(ctx context.Context, params *Params, payload *Payload) *EnqueuePasswordResetEmailUseCase {
	return &EnqueuePasswordResetEmailUseCase{ctx: ctx, Params: params, Payload: payload}
}

func (u *EnqueuePasswordResetEmailUseCase) Execute() error {
	job := kafka.EmailJob{
		Type:  "password_reset",
		To:    u.To,
		Token: u.Token,
	}

	return u.Producer.PublishMessage(u.ctx, u.To, job)
}
