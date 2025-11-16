package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"goauth/internal/constants"
	"goauth/internal/failure"
	"goauth/internal/logger"
	"goauth/internal/server"
	"goauth/internal/store"
	"goauth/internal/store/pg/repository"

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
	db := store.InitializeDB()
	defer db.Close()

	queries := repository.New(db)
	s := server.New(db, queries, servicePort)

	logger.Info().Msg("starting auth service on a port " + servicePort)

	go func() {
		logger.Info().Str("addr", s.ServerInstance.Addr).Msg("starting server")
		if err := s.ServerInstance.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			failure.FailedToStartServerError.WithErr(err).LogFatal()
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info().Msg("shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.ServerInstance.Shutdown(ctx); err != nil {
		failure.ForcedShutdownServerError.WithErr(err).LogFatal()
	}

	logger.Info().Msg("server stopped gracefully")
}
