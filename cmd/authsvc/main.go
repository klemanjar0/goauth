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
	"goauth/internal/kafka"
	"goauth/internal/logger"
	"goauth/internal/server"
	"goauth/internal/service"
	"goauth/internal/store"
)

func main() {
	cfg := config.Load()
	logger.Init(cfg.IsDevelopment)
	logger.Info().Msg("logger ready for use")
	db := store.InitializeDB(cfg)
	defer db.Close()

	redisClient := store.InitRedisClient(cfg)
	defer redisClient.Close()

	brokers := cfg.KafkaBrokers
	producer := kafka.NewProducer(kafka.ProducerConfig{
		Brokers: brokers,
		Topic:   service.EmailTopic,
	})
	defer producer.Close()

	emailService := service.NewEmailService(producer)

	kafkaServices := &server.KafkaServices{
		EmailService: emailService,
	}

	s := server.New(db, cfg, redisClient, kafkaServices)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	numConsumers := 3
	for i := range numConsumers {
		consumer := kafka.NewConsumer(kafka.ConsumerConfig{
			Brokers: brokers,
			Topic:   service.EmailTopic,
			GroupID: "email-workers",
			Handler: service.HandleEmailMessage,
		})

		go func(c *kafka.Consumer, id int) {
			if err := c.Start(ctx); err != nil {
				logger.Error().
					Err(err).
					Int("consumer_id", id).
					Msg("consumer stopped with error")
			}
		}(consumer, i)
	}

	go func() {
		logger.Info().Str("addr", s.ServerInstance.Addr).Msg("starting server")
		if err := s.ServerInstance.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal().Err(err).Msg(failure.ErrFailedToStartServer.Error())
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	cancel()

	time.Sleep(5 * time.Second)

	logger.Info().Msg("shutting down server...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := s.ServerInstance.Shutdown(shutdownCtx); err != nil {
		logger.Fatal().Err(err).Msg(failure.ErrForcedShutdownServer.Error())
	}

	logger.Info().Msg("server stopped gracefully")
}
