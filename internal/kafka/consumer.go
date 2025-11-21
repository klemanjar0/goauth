package kafka

import (
	"context"
	"time"

	"goauth/internal/logger"

	"github.com/segmentio/kafka-go"
)

type Consumer struct {
	reader  *kafka.Reader
	handler MessageHandler
}

type MessageHandler func(ctx context.Context, key, value []byte) error

type ConsumerConfig struct {
	Brokers []string
	Topic   string
	GroupID string
	Handler MessageHandler
}

func NewConsumer(cfg ConsumerConfig) *Consumer {
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        cfg.Brokers,
		Topic:          cfg.Topic,
		GroupID:        cfg.GroupID,
		MinBytes:       10e3, // 10KB
		MaxBytes:       10e6, // 10MB
		CommitInterval: time.Second,
		StartOffset:    kafka.LastOffset,
		MaxAttempts:    3,
		ReadBackoffMin: 100 * time.Millisecond,
		ReadBackoffMax: 1 * time.Second,
	})

	return &Consumer{
		reader:  reader,
		handler: cfg.Handler,
	}
}

func (c *Consumer) Start(ctx context.Context) error {
	logger.Info().
		Str("topic", c.reader.Config().Topic).
		Str("group_id", c.reader.Config().GroupID).
		Msg("kafka consumer started")

	for {
		select {
		case <-ctx.Done():
			logger.Info().Msg("kafka consumer stopped")
			return c.reader.Close()
		default:
			msg, err := c.reader.FetchMessage(ctx)
			if err != nil {
				if err == context.Canceled {
					return nil
				}
				logger.Error().Err(err).Msg("failed to fetch message")
				time.Sleep(time.Second)
				continue
			}

			if err := c.processMessage(ctx, msg); err != nil {
				logger.Error().
					Err(err).
					Str("topic", msg.Topic).
					Int("partition", msg.Partition).
					Int64("offset", msg.Offset).
					Msg("failed to process message")
				continue
			}

			if err := c.reader.CommitMessages(ctx, msg); err != nil {
				logger.Error().Err(err).Msg("failed to commit message")
			}
		}
	}
}

func (c *Consumer) processMessage(ctx context.Context, msg kafka.Message) error {
	logger.Debug().
		Str("topic", msg.Topic).
		Int("partition", msg.Partition).
		Int64("offset", msg.Offset).
		Str("key", string(msg.Key)).
		Msg("processing message")

	return c.handler(ctx, msg.Key, msg.Value)
}

func (c *Consumer) Close() error {
	if c.reader != nil {
		return c.reader.Close()
	}
	return nil
}
