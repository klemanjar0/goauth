package isaccountlockedusecase

import (
	"context"
	"fmt"
	"goauth/internal/constants"

	"github.com/redis/go-redis/v9"
)

type Params struct {
	Redis *redis.Client
}
type Payload struct {
	Email string
}

type IsAccountLockedUseCase struct {
	ctx context.Context

	*Params
	*Payload
}

func New(ctx context.Context, params *Params, payload *Payload) *IsAccountLockedUseCase {
	return &IsAccountLockedUseCase{ctx: ctx, Params: params, Payload: payload}
}

func (u *IsAccountLockedUseCase) Execute() bool {
	lockKey := fmt.Sprintf(constants.RedisKeyAccountLocked, u.Email)
	exists, err := u.Redis.Exists(u.ctx, lockKey).Result()
	return err == nil && exists > 0
}
