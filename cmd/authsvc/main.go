package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"goauth/internal/config"
	"goauth/internal/failure"
	"goauth/internal/logger"
	"goauth/internal/server"
	"goauth/internal/store"
	"goauth/internal/store/pg/repository"
)

func main() {
	cfg := config.Load()
	logger.Init(cfg.IsDevelopment)
	logger.Info().Msg("logger ready for use")
	db := store.InitializeDB()
	defer db.Close()

	redisClient := store.InitRedisClient(cfg)
	defer redisClient.Close()

	queries := repository.New(db)
	s := server.New(db, queries, cfg)

	go func() {
		logger.Info().Str("addr", s.ServerInstance.Addr).Msg("starting server")
		if err := s.ServerInstance.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			code, msg := failure.FailedToStartServerError.Get()
			logger.Fatal().Err(err).Int("code", code).Msg(msg)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info().Msg("shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.ServerInstance.Shutdown(ctx); err != nil {
		code, msg := failure.ForcedShutdownServerError.Get()
		logger.Fatal().Err(err).Int("code", code).Msg(msg)
	}

	logger.Info().Msg("server stopped gracefully")
}
