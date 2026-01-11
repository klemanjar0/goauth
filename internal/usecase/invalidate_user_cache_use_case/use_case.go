package invalidateusercacheusecase

import (
	"context"
	"goauth/internal/logger"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/redis/go-redis/v9"
)

type Params struct {
	Redis *redis.Client
}

type Payload struct {
	UserID pgtype.UUID
}

type InvalidateUserCacheUseCase struct {
	ctx context.Context
	*Params
	*Payload
}

func New(ctx context.Context, params *Params, payload *Payload) *InvalidateUserCacheUseCase {
	return &InvalidateUserCacheUseCase{
		ctx:     ctx,
		Params:  params,
		Payload: payload,
	}
}

func (u *InvalidateUserCacheUseCase) Execute() {
	cacheKey := "user:" + u.UserID.String()
	err := u.Redis.Del(u.ctx, cacheKey).Err()
	if err != nil {
		logger.Warn().
			Err(err).
			Str("user_id", u.UserID.String()).
			Msg("failed to invalidate user cache")
	}
}
