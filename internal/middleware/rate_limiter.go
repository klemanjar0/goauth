package middleware

import (
	"context"
	"fmt"
	"goauth/internal"
	"goauth/internal/logger"
	"goauth/internal/utility"
	"net/http"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// unused

type RateLimiterConfig struct {
	RequestsPerWindow int
	WindowDuration    time.Duration
	KeyPrefix         string
	SkipSuccessHeader bool
}

type RateLimiter struct {
	redis  *redis.Client
	config RateLimiterConfig
}

func NewRateLimiter(redisClient *redis.Client, config RateLimiterConfig) *RateLimiter {
	if config.KeyPrefix == "" {
		config.KeyPrefix = "ratelimit"
	}
	if config.RequestsPerWindow <= 0 {
		config.RequestsPerWindow = 100
	}
	if config.WindowDuration <= 0 {
		config.WindowDuration = time.Minute
	}

	return &RateLimiter{
		redis:  redisClient,
		config: config,
	}
}

func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		clientIP := utility.GetClientIP(r)

		allowed, remaining, resetTime, err := rl.checkRateLimit(ctx, clientIP)
		if err != nil {
			logger.Error().
				Err(err).
				Str("client_ip", clientIP).
				Msg("rate limiter error")
			next.ServeHTTP(w, r)
			return
		}

		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rl.config.RequestsPerWindow))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))

		if !allowed {
			retryAfter := int(time.Until(resetTime).Seconds())
			if retryAfter < 0 {
				retryAfter = 0
			}

			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))

			logger.Warn().
				Str("client_ip", clientIP).
				Str("path", r.URL.Path).
				Int("limit", rl.config.RequestsPerWindow).
				Msg("rate limit exceeded")

			internal.
				Respond(w).
				Status(http.StatusTooManyRequests).
				Message("rate limit exceeded. please try again later").
				Send()
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) checkRateLimit(ctx context.Context, identifier string) (allowed bool, remaining int, resetTime time.Time, err error) {
	now := time.Now()
	windowStart := now.Truncate(rl.config.WindowDuration)
	resetTime = windowStart.Add(rl.config.WindowDuration)

	key := fmt.Sprintf("%s:%s:%d", rl.config.KeyPrefix, identifier, windowStart.Unix())

	pipe := rl.redis.Pipeline()
	incrCmd := pipe.Incr(ctx, key)
	pipe.ExpireAt(ctx, key, resetTime)
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

func (rl *RateLimiter) MiddlewareWithCustomKey(keyFunc func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			key := keyFunc(r)

			if key == "" {
				next.ServeHTTP(w, r)
				return
			}

			allowed, remaining, resetTime, err := rl.checkRateLimit(ctx, key)
			if err != nil {
				logger.Error().
					Err(err).
					Str("key", key).
					Msg("rate limiter error")
				next.ServeHTTP(w, r)
				return
			}

			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rl.config.RequestsPerWindow))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetTime.Unix(), 10))

			if !allowed {
				retryAfter := int(time.Until(resetTime).Seconds())
				if retryAfter < 0 {
					retryAfter = 0
				}

				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))

				logger.Warn().
					Str("key", key).
					Str("path", r.URL.Path).
					Int("limit", rl.config.RequestsPerWindow).
					Msg("rate limit exceeded")

				internal.
					Respond(w).
					Status(http.StatusTooManyRequests).
					Message("rate limit exceeded. please try again later").
					Send()
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
