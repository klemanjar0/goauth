package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"goauth/internal/failure"
	"goauth/internal/store"
	authenticateuserusecase "goauth/internal/usecase/authenticate_user_use_case"
	getuserbyemailusecase "goauth/internal/usecase/get_user_by_email_use_case"
	getuserbyidusecase "goauth/internal/usecase/get_user_by_id_use_case"
	invalidateusercacheusecase "goauth/internal/usecase/invalidate_user_cache_use_case"
	loginusecase "goauth/internal/usecase/login_use_case"
	logoutusecase "goauth/internal/usecase/logout_use_case"
	refreshaccesstokenusecase "goauth/internal/usecase/refresh_access_token_use_case"
	registerusecase "goauth/internal/usecase/register_use_case"
	verifyaccesstokenusecase "goauth/internal/usecase/verify_access_token_use_case"
	"goauth/internal/utility"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/redis/go-redis/v9"

	"goauth/internal/auth"
	"goauth/internal/logger"
	"goauth/internal/store/pg/repository"
)

type UserService struct {
	store        *store.Store
	redis        *redis.Client
	hasher       *auth.PasswordHasher
	emailService *EmailService
}

type VerifyTokenResponse struct {
	Valid       bool
	UserID      pgtype.UUID
	Email       string
	Permissions int64
	ExpiresAt   time.Time
}

type ResetPasswordPayload struct {
	Token       string
	NewPassword string
	IP          string
	UserAgent   string
}

func NewUserService(store *store.Store, redisClient *redis.Client, emailService *EmailService) *UserService {
	return &UserService{
		store:        store,
		redis:        redisClient,
		hasher:       auth.NewPasswordHasher(),
		emailService: emailService,
	}
}

func (s *UserService) RegisterUser(
	ctx context.Context,
	req registerusecase.Payload,
) (*registerusecase.Response, error) {
	return registerusecase.New(
		ctx,
		&registerusecase.Params{
			Store:       s.store,
			RedisClient: s.redis,
			Hasher:      s.hasher,
		},
		&req,
	).Execute()
}

func (s *UserService) GetUserByIDWithCache(ctx context.Context, userID pgtype.UUID) (*repository.User, error) {
	return getuserbyidusecase.New(ctx, &getuserbyidusecase.Params{
		Store: s.store,
		Redis: s.redis,
	}, &getuserbyidusecase.Payload{UserID: userID}).Execute()
}

func (s *UserService) InvalidateUserCache(ctx context.Context, userID pgtype.UUID) {
	invalidateusercacheusecase.
		New(ctx,
			&invalidateusercacheusecase.Params{
				Redis: s.redis,
			},
			&invalidateusercacheusecase.Payload{
				UserID: userID,
			}).
		Execute()
}

func (s *UserService) GetUserByEmail(ctx context.Context, email string) (*repository.User, error) {
	return getuserbyemailusecase.
		New(ctx, &getuserbyemailusecase.Params{Store: s.store}, &getuserbyemailusecase.Payload{Email: email}).
		Execute()
}

func (s *UserService) AuthenticateUser(ctx context.Context, email, password string) (*repository.User, error) {
	return authenticateuserusecase.
		New(ctx,
			&authenticateuserusecase.Params{Store: s.store, Redis: s.redis, Hasher: s.hasher},
			&authenticateuserusecase.Payload{Email: email, Password: password},
		).
		Execute()
}

func (s *UserService) VerifyAccessToken(ctx context.Context, req verifyaccesstokenusecase.Payload) (*verifyaccesstokenusecase.Response, error) {
	return verifyaccesstokenusecase.New(
		ctx,
		&verifyaccesstokenusecase.Params{
			Store: s.store,
			Redis: s.redis,
		},
		&req,
	).Execute()
}

func (s *UserService) LoginUser(ctx context.Context, req loginusecase.Payload) (*loginusecase.Response, error) {
	return loginusecase.New(
		ctx,
		&loginusecase.Params{
			Store:  s.store,
			Redis:  s.redis,
			Hasher: s.hasher,
		},
		&req,
	).Execute()
}

func (s *UserService) RefreshAccessToken(ctx context.Context, req refreshaccesstokenusecase.Payload) (*refreshaccesstokenusecase.Response, error) {
	return refreshaccesstokenusecase.
		New(
			ctx,
			&refreshaccesstokenusecase.Params{
				Store: s.store,
				Redis: s.redis,
			},
			&req,
		).Execute()
}

func (s *UserService) LogoutUser(ctx context.Context, accessToken string, userID pgtype.UUID, ip, userAgent string) error {
	return logoutusecase.New(
		ctx,
		&logoutusecase.Params{Store: s.store, Redis: s.redis},
		&logoutusecase.Payload{AccessToken: accessToken, UserID: userID, IP: ip, UserAgent: userAgent},
	).Execute()
}

func (s *UserService) createAuditLog(ctx context.Context, userID pgtype.UUID, eventType, ip, userAgent string, payload map[string]any) error {
	params := repository.CreateAuditLogParams{
		EventType: eventType,
	}

	if userID.Valid {
		params.UserID = userID
	}

	if ip != "" {
		addr, err := netip.ParseAddr(ip)
		if err == nil {
			params.Ip = &addr
		}
	}

	if userAgent != "" {
		params.Ua = pgtype.Text{String: userAgent, Valid: true}
	}

	if payload != nil {
		jsonBytes, err := json.Marshal(payload)
		if err == nil {
			params.Payload = jsonBytes
		}
	}

	_, err := s.store.Queries.CreateAuditLog(ctx, params)
	return err
}

func (s *UserService) SendVerificationEmail(ctx context.Context, user *registerusecase.Response) error {
	token := uuid.New().String()
	params := repository.CreateEmailVerificationTokenParams{
		UserID:    user.UserID,
		TokenHash: auth.HashToken256(token),
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(24 * time.Hour), Valid: true},
	}

	_, err := s.store.Queries.CreateEmailVerificationToken(ctx, params)
	if err != nil {
		logger.Error().
			Str("email", user.Email).
			Err(err).
			Msg("failed to create email verification token")
		return err
	}

	if err := s.emailService.EnqueueVerificationEmail(ctx, user.Email, token); err != nil {
		logger.Error().
			Err(err).
			Str("email", user.Email).
			Msg("failed to enqueue verification email")
		return err
	}

	logger.Info().
		Str("email", user.Email).
		Str("user_id", user.UserID.String()).
		Msg("verification email queued")

	return nil
}

func (s *UserService) SendPasswordResetEmail(ctx context.Context, email string) error {
	var user *repository.User
	var err error
	user, err = s.GetUserByEmail(ctx, email)

	if err != nil || user == nil {
		logger.Warn().Str("email", email).Msg("password reset requested for non-existent email")
		return nil
	}

	if !user.IsActive.Bool {
		logger.Warn().Msg("user inactive")
		return nil
	}

	token := uuid.New().String()
	params := repository.CreatePasswordResetTokenParams{
		UserID:    user.ID,
		TokenHash: auth.HashToken256(token),
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(24 * time.Hour), Valid: true},
	}

	_, err = s.store.Queries.CreatePasswordResetToken(ctx, params)

	if err != nil {
		logger.Error().
			Str("email", user.Email).
			Err(err).
			Msg("failed to create password reset token on db")
		return err
	}

	if err := s.emailService.EnqueuePasswordResetEmail(ctx, user.Email, token); err != nil {
		logger.Error().
			Err(err).
			Str("email", user.Email).
			Msg("failed to enqueue password reset email")
		return err
	}

	logger.Info().
		Str("email", user.Email).
		Msg("password reset email queued")

	return nil
}

func (s *UserService) ResetPassword(ctx context.Context, payload ResetPasswordPayload) error {
	var user *repository.User
	var err error

	tokenHash := auth.HashToken256(payload.Token)

	var token repository.PasswordResetToken
	token, err = s.store.Queries.GetPasswordResetTokenByHash(ctx, tokenHash)

	if err != nil {
		logger.Error().
			Err(err).
			Msg("token is not found")
		return failure.ErrTokenInvalid
	}

	user, err = s.GetUserByIDWithCache(ctx, token.UserID)

	if err != nil {
		logger.Error().
			Err(err).
			Str("uuid", token.UserID.String()).
			Msg("failed to get user data with token")
		return failure.ErrDatabaseError
	}

	if err := utility.ValidatePassword(payload.NewPassword); err != nil {
		logger.Warn().
			Str("email", user.Email).
			Err(err).
			Msg("weak password during registration")
		return failure.ErrPasswordTooWeak
	}

	passwordHash, err := s.hasher.HashPassword(payload.NewPassword)
	if err != nil {
		logger.Error().
			Err(err).
			Str("email", user.Email).
			Msg("failed to hash password")
		return failure.ErrPasswordHashError
	}

	err = s.store.ExecTx(ctx, func(tx *repository.Queries) error {
		_, updateErr :=
			tx.UpdateUserPassword(ctx, repository.UpdateUserPasswordParams{
				ID:           user.ID,
				PasswordHash: passwordHash,
			})

		if updateErr != nil {
			logger.Error().
				Err(updateErr).
				Msg("failed to update password")
			return updateErr
		}

		invErr := tx.MarkPasswordResetTokenUsed(ctx, token.ID)

		if invErr != nil {
			logger.Error().
				Err(invErr).
				Msg("failed to invalidate token")

			return invErr
		}

		if err := tx.RevokeAllUserTokens(ctx, user.ID); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		logger.Error().
			Err(err).
			Str("email", user.Email).
			Msg("password change transaction failed")
		return failure.ErrPasswordReset
	}

	s.InvalidateUserCache(ctx, user.ID)

	err = s.createAuditLog(ctx, user.ID, "user_password_reset", payload.IP, payload.UserAgent, map[string]any{
		"reason": "user_initiated",
	})

	if err != nil {
		logger.Error().
			Err(err).
			Msg("createAuditLog failed")
	}

	return nil
}

func (s *UserService) VerifyEmail(ctx context.Context, token string) error {
	if token == "" {
		return failure.ErrInvalidToken
	}

	tokenHash := auth.HashToken256(token)
	verificationToken, err := s.store.Queries.GetEmailVerificationTokenByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.Warn().
				Str("token", token).
				Msg("email verification token not found or expired")
			return failure.ErrInvalidToken
		}
		logger.Error().
			Err(err).
			Msg("database error while fetching email verification token")
		return failure.ErrDatabaseError
	}

	err = s.store.ExecTx(ctx, func(tx *repository.Queries) error {
		if err := tx.MarkEmailVerificationTokenUsed(ctx, verificationToken.ID); err != nil {
			logger.Error().
				Err(err).
				Str("token_id", verificationToken.ID.String()).
				Msg("failed to mark email verification token as used")
			return failure.ErrDatabaseError
		}

		_, updateErr := tx.UpdateUser(ctx, repository.UpdateUserParams{
			ID:             verificationToken.UserID,
			EmailConfirmed: pgtype.Bool{Bool: true, Valid: true},
		})
		if updateErr != nil {
			logger.Error().
				Err(updateErr).
				Str("user_id", verificationToken.UserID.String()).
				Msg("failed to update user email_confirmed status")
			return failure.ErrDatabaseError
		}

		return nil
	})

	if err != nil {
		logger.Error().
			Err(err).
			Str("user_id", verificationToken.UserID.String()).
			Msg("email verification transaction failed")
		return failure.ErrDatabaseError
	}

	s.InvalidateUserCache(ctx, verificationToken.UserID)

	// Create audit log for email verification
	err = s.createAuditLog(ctx, verificationToken.UserID, "email_verified", "", "", map[string]any{
		"token_id": verificationToken.ID.String(),
	})
	if err != nil {
		logger.Warn().
			Err(err).
			Str("user_id", verificationToken.UserID.String()).
			Msg("failed to create audit log for email verification")
	}

	logger.Info().
		Str("user_id", verificationToken.UserID.String()).
		Msg("email verified successfully")

	return nil
}
