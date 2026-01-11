package resetfailedloginsusecase

import (
	"context"
	"fmt"
	"goauth/internal/constants"
	"goauth/internal/logger"

	"github.com/redis/go-redis/v9"
)

type Params struct {
	Redis *redis.Client
}
type Payload struct {
	Email string
}

type ResetFailedLoginsUseCase struct {
	ctx context.Context

	*Params
	*Payload
}

func New(ctx context.Context, params *Params, payload *Payload) *ResetFailedLoginsUseCase {
	return &ResetFailedLoginsUseCase{ctx: ctx, Params: params, Payload: payload}
}

func (u *ResetFailedLoginsUseCase) Execute() error {
	key := fmt.Sprintf(constants.RedisKeyFailedLogin, u.Email)
	lockKey := fmt.Sprintf(constants.RedisKeyAccountLocked, u.Email)
	if err := u.Redis.Del(u.ctx, key, lockKey).Err(); err != nil {
		logger.Warn().Err(err).Str("email", u.Email).Msg("failed to reset failed logins")
		return err
	}
	return nil
}
