package config

import (
	"goauth/internal/auth"
	"goauth/internal/constants"
	"goauth/internal/email"
	"goauth/internal/failure"
	"goauth/internal/logger"
	"strings"

	"os"
	"time"

	"github.com/joho/godotenv"
)

type RedisConfig struct {
	Host     string
	Port     string
	Password string
	DB       int
}

type GRPCConfig struct {
	Port       string
	TLSEnabled bool
	CertFile   string
	KeyFile    string
}

type PoolConfig struct {
	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration
}

type Config struct {
	IsDevelopment        bool
	RunMigrationsOnStart bool
	Port                 string
	RedisConfig          RedisConfig
	KafkaBrokers         []string
	GRPCConfig           GRPCConfig
	AllowedOrigins       []string
	PoolConfig           PoolConfig
}

func Load() *Config {
	logger.Info().Msg("loading service configuration")
	if err := godotenv.Load(); err != nil {
		logger.Warn().Err(err).Msg(failure.ErrEnvironmentLocalFile.Error())
	}

	isDev := getEnv(constants.ENV, constants.DEVELOPMENT) == constants.DEVELOPMENT

	// dev purposes only!
	RunMigrationsOnStart := false

	if isDev {
		logger.Info().Msg("service is running is development mode")
	} else {
		logger.Info().Msg("service is running is production mode")
	}

	port := getEnv(constants.PORT, "8080")

	grpcConfig := GRPCConfig{
		Port:       getEnv(constants.GRPC_PORT, "50051"),
		TLSEnabled: getEnv(constants.GRPC_TLS_ENABLED, "false") == "true",
		CertFile:   getEnv(constants.GRPC_CERT_FILE, ""),
		KeyFile:    getEnv(constants.GRPC_KEY_FILE, ""),
	}

	logger.Info().Msg("port" + port)

	redisConfig := RedisConfig{
		Host:     getEnv(constants.REDIS_HOST, "localhost"),
		Port:     getEnv(constants.REDIS_PORT, "6379"),
		Password: getEnv(constants.REDIS_PASSWORD, ""),
		DB:       0,
	}

	poolConfig := PoolConfig{
		MinConns:          0,
		MaxConns:          50,
		MaxConnLifetime:   time.Hour,
		MaxConnIdleTime:   time.Minute * 30,
		HealthCheckPeriod: time.Minute,
	}

	auth.Init(auth.JWTConfig{
		AccessSecret:  getEnv(constants.JWT_ACCESS_SECRET, ""),
		RefreshSecret: getEnv(constants.JWT_REFRESH_SECRET, ""),
		AccessTTL:     15 * time.Minute,
		RefreshTTL:    7 * 24 * time.Hour,
	})

	email.Init(email.Config{
		SMTPHost: getEnv(constants.SMTP_HOST, "smtp.gmail.com"),
		SMTPPort: getEnv(constants.SMTP_PORT, "587"),
		SMTPUser: getEnv(constants.SMTP_USER, "noreply"),
		From:     getEnv(constants.SMTP_FROM, "noreply@yourapp.com"),
		Password: getEnv(constants.SMTP_PASSWORD, ""),
	})

	brokers := strings.Split(getEnv("KAFKA_BROKERS", "localhost:9092"), ",")

	// Parse allowed origins for CORS
	allowedOrigins := parseAllowedOrigins(getEnv(constants.CORS_ALLOWED_ORIGINS, ""))

	logger.Info().Msg("loading service configuration end")

	return &Config{
		IsDevelopment:        isDev,
		Port:                 port,
		RedisConfig:          redisConfig,
		KafkaBrokers:         brokers,
		RunMigrationsOnStart: RunMigrationsOnStart,
		GRPCConfig:           grpcConfig,
		AllowedOrigins:       allowedOrigins,
		PoolConfig:           poolConfig,
	}
}

func parseAllowedOrigins(originsEnv string) []string {
	if originsEnv == "" {
		return []string{}
	}

	origins := strings.Split(originsEnv, ",")
	result := make([]string, 0, len(origins))

	for _, origin := range origins {
		trimmed := strings.TrimSpace(origin)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}

	return result
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
