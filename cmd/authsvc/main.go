package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"goauth/internal/config"
	"goauth/internal/kafka"
	"goauth/internal/logger"
	"goauth/internal/server"
	"goauth/internal/store"
	handleemailmessageusecase "goauth/internal/usecase/handle_email_message_use_case"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// # DEVELOPMENT MODE SHOULD BE SET MANUALLY #
	logger.Init(true)

	cfg := config.Load()
	logger.Info().Msg("logger ready for use")
	db := store.InitializeDB(ctx, cfg)
	defer db.Close()

	redisClient := store.InitRedisClient(ctx, cfg)
	defer redisClient.Close()

	brokers := cfg.KafkaBrokers
	producer := kafka.NewProducer(kafka.ProducerConfig{
		Brokers: brokers,
		Topic:   kafka.EmailTopic,
	})
	defer producer.Close()

	s := server.New(db, cfg, redisClient, producer)

	var wg sync.WaitGroup

	numConsumers := 3
	consumers := make([]*kafka.Consumer, numConsumers)
	for i := range numConsumers {
		consumer := kafka.NewConsumer(kafka.ConsumerConfig{
			Brokers: brokers,
			Topic:   kafka.EmailTopic,
			GroupID: "email-workers",
			Handler: func(ctx context.Context, key, value []byte) error {
				return handleemailmessageusecase.
					New(
						ctx,
						&handleemailmessageusecase.Params{},
						&handleemailmessageusecase.Payload{
							Key:   key,
							Value: value,
						},
					).
					Execute()
			},
		})
		consumers[i] = consumer

		wg.Add(1)
		go func(c *kafka.Consumer, id int) {
			defer wg.Done()
			if err := c.Start(ctx); err != nil {
				logger.Error().Err(err).Int("consumer_id", id).Msg("consumer stopped with error")
			}
			logger.Info().Int("consumer_id", id).Msg("consumer shutdown complete")
		}(consumer, i)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Info().Str("addr", s.ServerInstance.Addr).Msg("starting HTTP server")
		if err := s.ServerInstance.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error().Err(err).Msg("HTTP server error")
		}
		logger.Info().Msg("HTTP server shutdown complete")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Info().Msg("starting gRPC server")
		if err := s.GrpcInstance.Start(); err != nil {
			logger.Error().Err(err).Msg("gRPC server error")
		}
		logger.Info().Msg("gRPC server shutdown complete")
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info().Msg("shutdown signal received, starting graceful shutdown...")

	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := s.ServerInstance.Shutdown(shutdownCtx); err != nil {
		logger.Error().Err(err).Msg("HTTP server forced shutdown")
	}

	s.GrpcInstance.Stop()

	logger.Info().Msg("waiting for all workers to finish...")
	wg.Wait()

	logger.Info().Msg("server stopped gracefully")
}
