package grpc

import (
	"context"
	"fmt"
	"time"

	"goauth/internal/logger"

	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type RateLimiterConfig struct {
	RequestsPerWindow int
	WindowDuration    time.Duration
	KeyPrefix         string
}

type GRPCRateLimiter struct {
	redis  *redis.Client
	config RateLimiterConfig
}

func NewGRPCRateLimiter(redis *redis.Client, config RateLimiterConfig) *GRPCRateLimiter {
	return &GRPCRateLimiter{
		redis:  redis,
		config: config,
	}
}

// rateLimitInterceptor implements rate limiting for gRPC requests
func (rl *GRPCRateLimiter) Interceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		clientID := rl.getClientIdentifier(ctx)

		key := fmt.Sprintf("%s:%s:%s", rl.config.KeyPrefix, info.FullMethod, clientID)

		allowed, remaining, resetTime, err := rl.checkRateLimit(ctx, key)
		if err != nil {
			logger.Error().Err(err).Str("key", key).Msg("rate limit check failed")
			return handler(ctx, req)
		}

		header := metadata.Pairs(
			"x-ratelimit-limit", fmt.Sprintf("%d", rl.config.RequestsPerWindow),
			"x-ratelimit-remaining", fmt.Sprintf("%d", remaining),
			"x-ratelimit-reset", fmt.Sprintf("%d", resetTime),
		)
		if err := grpc.SetHeader(ctx, header); err != nil {
			logger.Warn().Err(err).Msg("failed to set rate limit headers")
		}

		if !allowed {
			logger.Warn().
				Str("client_id", clientID).
				Str("method", info.FullMethod).
				Int("limit", rl.config.RequestsPerWindow).
				Msg("rate limit exceeded")

			return nil, status.Errorf(
				codes.ResourceExhausted,
				"rate limit exceeded, try again in %d seconds",
				resetTime-time.Now().Unix(),
			)
		}

		return handler(ctx, req)
	}
}

func (rl *GRPCRateLimiter) getClientIdentifier(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if userIDs := md.Get("user-id"); len(userIDs) > 0 {
			return fmt.Sprintf("user:%s", userIDs[0])
		}
	}

	if p, ok := peer.FromContext(ctx); ok {
		return fmt.Sprintf("ip:%s", p.Addr.String())
	}

	return "unknown"
}

func (rl *GRPCRateLimiter) checkRateLimit(ctx context.Context, key string) (allowed bool, remaining int, resetTime int64, err error) {
	now := time.Now()
	windowStart := now.Unix()
	resetTime = windowStart + int64(rl.config.WindowDuration.Seconds())

	pipe := rl.redis.Pipeline()

	incrCmd := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, rl.config.WindowDuration)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return false, 0, resetTime, fmt.Errorf("redis pipeline error: %w", err)
	}

	count := int(incrCmd.Val())
	remaining = rl.config.RequestsPerWindow - count
	if remaining < 0 {
		remaining = 0
	}

	allowed = count <= rl.config.RequestsPerWindow

	return allowed, remaining, resetTime, nil
}
