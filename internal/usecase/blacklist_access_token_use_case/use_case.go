package blacklistaccesstokenusecase

import (
	"context"
	"fmt"
	"goauth/internal/auth"
	"goauth/internal/constants"
	"goauth/internal/failure"
	"goauth/internal/logger"
	"time"

	"github.com/redis/go-redis/v9"
)

type Params struct {
	Redis *redis.Client
}
type Payload struct {
	Token string
}

type BlacklistAccessTokenUseCase struct {
	ctx context.Context

	*Params
	*Payload
}

func New(ctx context.Context, params *Params, payload *Payload) *BlacklistAccessTokenUseCase {
	return &BlacklistAccessTokenUseCase{ctx: ctx, Params: params, Payload: payload}
}

func (u *BlacklistAccessTokenUseCase) Execute() error {
	claims, err := auth.ValidateAccessToken(u.Token)
	if err != nil {
		logger.Debug().
			Err(err).
			Msg("attempted to blacklist invalid token")
		return nil
	}

	ttl := time.Until(claims.ExpiresAt.Time)
	if ttl <= 0 {
		return nil
	}

	blacklistKey := fmt.Sprintf(constants.RedisKeyAccessBlacklist, u.Token)
	err = u.Redis.Set(u.ctx, blacklistKey, "revoked", ttl).Err()
	if err != nil {
		logger.Error().
			Err(err).
			Str("token_preview", u.Token[:20]+"...").
			Msg("failed to blacklist token in redis")
		return failure.ErrDatabaseError
	}

	logger.Info().
		Str("user_id", claims.UserID).
		Dur("ttl", ttl).
		Msg("access token blacklisted successfully")

	return nil
}
