package recordfailedloginusecase

import (
	"context"
	"fmt"
	"goauth/internal/constants"
	"goauth/internal/logger"
	"time"

	"github.com/redis/go-redis/v9"
)

type Params struct {
	Redis *redis.Client
}
type Payload struct {
	Email string
}

type RecordFailedLoginUseCase struct {
	ctx context.Context

	*Params
	*Payload
}

func New(ctx context.Context, params *Params, payload *Payload) *RecordFailedLoginUseCase {
	return &RecordFailedLoginUseCase{ctx: ctx, Params: params, Payload: payload}
}

func (u *RecordFailedLoginUseCase) Execute() error {
	key := fmt.Sprintf(constants.RedisKeyFailedLogin, u.Email)

	count, err := u.Redis.Incr(u.ctx, key).Result()
	if err != nil {
		return err
	}

	if count == 1 {
		if err := u.Redis.Expire(u.ctx, key, 15*time.Minute).Err(); err != nil {
			logger.Warn().Err(err).Msg("failed to set expiry on failed login counter")
			// can be skipped
		}
	}

	if count >= 5 {
		lockKey := fmt.Sprintf(constants.RedisKeyAccountLocked, u.Email)
		u.Redis.Set(u.ctx, lockKey, "locked", 30*time.Minute)
		logger.Warn().Str("email", u.Email).Msg("account locked due to failed login attempts")
	}

	return nil
}
