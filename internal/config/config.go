package config

import (
	"goauth/internal/auth"
	"goauth/internal/constants"
	"goauth/internal/failure"
	"goauth/internal/logger"
	"time"

	"os"

	"github.com/joho/godotenv"
)

type RedisConfig struct {
	Host     string
	Port     string
	Password string
	DB       int
}

type Config struct {
	IsDevelopment bool
	Port          string
	RedisConfig   RedisConfig
}

func Load() *Config {
	logger.Info().Msg("loading service configuration")
	if err := godotenv.Load(); err != nil {
		logger.Warn().Err(err).Msg(failure.ErrEnvironmentLocalFile.Error())
	}

	isDev := getEnv(constants.ENV, constants.DEVELOPMENT) == constants.DEVELOPMENT

	if isDev {
		logger.Info().Msg("service is running is development mode")
	} else {
		logger.Info().Msg("service is running is production mode")
	}

	port := getEnv(constants.PORT, "8080")

	logger.Info().Msg("port" + port)

	redisConfig := RedisConfig{
		Host:     getEnv(constants.REDIS_HOST, "localhost"),
		Port:     getEnv(constants.REDIS_PORT, "6379"),
		Password: getEnv(constants.REDIS_PASSWORD, ""),
		DB:       0,
	}

	auth.Init(auth.JWTConfig{
		AccessSecret:  getEnv(constants.JWT_ACCESS_SECRET, ""),
		RefreshSecret: getEnv(constants.JWT_REFRESH_SECRET, ""),
		AccessTTL:     15 * time.Minute,
		RefreshTTL:    7 * 24 * time.Hour,
	})

	logger.Info().Msg("loading service configuration end")

	return &Config{
		IsDevelopment: isDev,
		Port:          port,
		RedisConfig:   redisConfig,
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
