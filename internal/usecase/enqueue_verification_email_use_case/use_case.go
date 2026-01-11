package enqueueverificationemailusecase

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

type EnqueueVerificationEmailUseCase struct {
	ctx context.Context

	*Params
	*Payload
}

func New(ctx context.Context, params *Params, payload *Payload) *EnqueueVerificationEmailUseCase {
	return &EnqueueVerificationEmailUseCase{ctx: ctx, Params: params, Payload: payload}
}

func (u *EnqueueVerificationEmailUseCase) Execute() error {
	job := kafka.EmailJob{
		Type:  "verification",
		To:    u.To,
		Token: u.Token,
	}

	return u.Producer.PublishMessage(u.ctx, u.To, job)
}
