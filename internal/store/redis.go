package store

import (
	"context"
	"goauth/internal/config"
	"goauth/internal/failure"
	"goauth/internal/logger"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisClient struct {
	Client *redis.Client
}

func InitRedisClient(ctx context.Context, cfg *config.Config) *RedisClient {
	client := redis.NewClient(&redis.Options{
		Addr:         cfg.RedisConfig.Host + ":" + cfg.RedisConfig.Port,
		Password:     cfg.RedisConfig.Password,
		DB:           cfg.RedisConfig.DB,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolSize:     10,
		MinIdleConns: 5,
	})

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		logger.Fatal().Err(err).Msg(failure.ErrRedisClient.Error())
	}

	logger.Info().Msg("redis successfully connected")
	return &RedisClient{Client: client}
}

func (r RedisClient) Close() error {
	if r.Client != nil {
		return r.Client.Close()
	}
	return nil
}
