package main

import (
	"os"

	"goauth/internal/constants"
	"goauth/internal/failure"
	"goauth/internal/logger"
	"goauth/internal/store"

	"github.com/joho/godotenv"
)

func init() {
	if err := godotenv.Load(); err != nil {
		failure.EnvironmentLocalFileError.WithErr(err).Warn()
	}
}

func setupPort() string {
	port := os.Getenv(constants.PortEnv)
	if port == "" {
		port = "8080"
		failure.EnvironmentPortError.Warn()
	}

	return port
}

func main() {
	logger.Init(os.Getenv(constants.ENV))
	servicePort := setupPort()
	logger.Info().Msg("starting auth service on a port " + servicePort)
	db := store.InitializeDB()
	defer db.Close()
}
