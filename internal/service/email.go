package service

import (
	"context"
	"encoding/json"

	"goauth/internal/email"
	"goauth/internal/kafka"
	"goauth/internal/logger"
)

const (
	EmailTopic = "emails"
)

type EmailService struct {
	producer *kafka.Producer
}

type EmailJob struct {
	Type      string `json:"type"` // "verification", "password_reset", "welcome"
	To        string `json:"to"`
	Token     string `json:"token,omitempty"`
	ExtraData string `json:"extra_data,omitempty"`
}

func NewEmailService(producer *kafka.Producer) *EmailService {
	return &EmailService{producer: producer}
}

func (s *EmailService) EnqueueVerificationEmail(ctx context.Context, to, token string) error {
	job := EmailJob{
		Type:  "verification",
		To:    to,
		Token: token,
	}

	return s.producer.PublishMessage(ctx, to, job)
}

func (s *EmailService) EnqueuePasswordResetEmail(ctx context.Context, to, token string) error {
	job := EmailJob{
		Type:  "password_reset",
		To:    to,
		Token: token,
	}

	return s.producer.PublishMessage(ctx, to, job)
}

func HandleEmailMessage(ctx context.Context, key, value []byte) error {
	var job EmailJob
	if err := json.Unmarshal(value, &job); err != nil {
		logger.Error().Err(err).Msg("failed to unmarshal email job")
		return err
	}

	logger.Info().
		Str("type", job.Type).
		Str("to", job.To).
		Msg("processing email job")

	var err error
	switch job.Type {
	case "verification":
		err = email.SendVerificationEmail(job.To, job.Token)
	case "password_reset":
		err = email.SendPasswordResetEmail(job.To, job.Token)
	default:
		logger.Warn().Str("type", job.Type).Msg("unknown email type")
		return nil
	}

	if err != nil {
		logger.Error().
			Err(err).
			Str("type", job.Type).
			Str("to", job.To).
			Msg("failed to send email")
		return err
	}

	logger.Info().
		Str("type", job.Type).
		Str("to", job.To).
		Msg("email sent successfully")

	return nil
}
