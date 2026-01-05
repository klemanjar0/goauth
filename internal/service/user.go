package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"time"

	"goauth/internal/failure"
	"goauth/internal/store"
	"goauth/internal/utility"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/redis/go-redis/v9"

	"goauth/internal/auth"
	"goauth/internal/logger"
	"goauth/internal/store/pg/repository"
)

const (
	defaultPermissions = 0 // No special permissions by default
)

type UserService struct {
	store        *store.Store
	redis        *redis.Client
	hasher       *auth.PasswordHasher
	emailService *EmailService
}

type RefreshTokenRequest struct {
	RefreshToken string
	DeviceInfo   string
}

type RefreshTokenResponse struct {
	AccessToken      string
	RefreshToken     string
	RefreshTokenID   pgtype.UUID
	AccessExpiresIn  int64 // seconds until access token expires
	RefreshExpiresIn int64 // seconds until refresh token expires
}

type LoginResponse struct {
	UserID           pgtype.UUID
	Email            string
	Permissions      int64
	AccessToken      string
	RefreshToken     string
	RefreshTokenID   pgtype.UUID
	AccessExpiresIn  int64
	RefreshExpiresIn int64
}

type LoginRequest struct {
	Email      string
	Password   string
	DeviceInfo string
	IP         string
	UserAgent  string
}

type RegisterUserRequest struct {
	Email       string
	Password    string
	Permissions int64
	IP          string // For audit logging
	UserAgent   string // For audit logging
}

type RegisterUserResponse struct {
	UserID         pgtype.UUID
	Email          string
	Permissions    int64
	IsActive       bool
	EmailConfirmed bool
	CreatedAt      time.Time
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

func (s *UserService) RegisterUser(ctx context.Context, req RegisterUserRequest) (*RegisterUserResponse, error) {
	if err := utility.ValidateEmail(req.Email); err != nil {
		logger.Warn().
			Str("email", req.Email).
			Err(err).
			Msg("invalid email format during registration")
		return nil, err
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))

	if err := utility.ValidatePassword(req.Password); err != nil {
		logger.Warn().
			Str("email", email).
			Err(err).
			Msg("weak password during registration")
		return nil, err
	}

	existingUser, err := s.store.Queries.GetUserByEmail(ctx, email)
	if err == nil && existingUser.ID.Valid {
		logger.Warn().
			Str("email", email).
			Msg("attempted registration with existing email")

		_ = s.createAuditLog(ctx, pgtype.UUID{Valid: false}, "registration_failed_duplicate", req.IP, req.UserAgent, map[string]any{
			"email":  email,
			"reason": "duplicate_email",
		})

		return nil, failure.ErrUserAlreadyExists
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		logger.Error().
			Err(err).
			Str("email", email).
			Msg("database error while checking existing user")
		return nil, failure.ErrDatabaseError
	}

	passwordHash, err := s.hasher.HashPassword(req.Password)
	if err != nil {
		logger.Error().
			Err(err).
			Str("email", email).
			Msg("failed to hash password")
		return nil, failure.ErrPasswordHashError
	}

	permissions := req.Permissions
	if permissions == 0 {
		permissions = defaultPermissions
	}

	user, err := s.store.Queries.CreateUser(ctx, repository.CreateUserParams{
		Email:        email,
		PasswordHash: passwordHash,
		Permissions:  permissions,
	})
	if err != nil {
		logger.Error().
			Err(err).
			Str("email", email).
			Msg("failed to create user in database")
		return nil, failure.ErrDatabaseError
	}

	err = s.createAuditLog(ctx, user.ID, "user_registered", req.IP, req.UserAgent, map[string]any{
		"email":       email,
		"permissions": permissions,
	})
	if err != nil {
		logger.Warn().
			Err(err).
			Str("user_id", user.ID.String()).
			Msg("failed to create audit log for registration")
	}

	logger.Info().
		Str("user_id", user.ID.String()).
		Str("email", email).
		Msg("user registered successfully")

	return &RegisterUserResponse{
		UserID:         user.ID,
		Email:          user.Email,
		Permissions:    user.Permissions,
		IsActive:       user.IsActive.Bool,
		EmailConfirmed: user.EmailConfirmed.Bool,
		CreatedAt:      user.CreatedAt.Time,
	}, nil
}

func (s *UserService) GetUserByID(ctx context.Context, userID pgtype.UUID) (*repository.User, error) {
	user, err := s.store.Queries.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, failure.ErrUserNotFound
		}
		logger.Error().
			Err(err).
			Str("user_id", userID.String()).
			Msg("database error while fetching user")
		return nil, failure.ErrDatabaseError
	}
	return &user, nil
}

func (s *UserService) GetUserByIDWithCache(ctx context.Context, userID pgtype.UUID) (*repository.User, error) {
	cacheKey := "user:" + userID.String()

	cachedData, err := s.redis.Get(ctx, cacheKey).Result()
	if err == nil && cachedData != "" {
		var user repository.User
		if err := json.Unmarshal([]byte(cachedData), &user); err == nil {
			logger.Debug().
				Str("user_id", userID.String()).
				Msg("user fetched from cache")
			return &user, nil
		}
	}

	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	userData, err := json.Marshal(user)
	if err == nil {
		err = s.redis.Set(ctx, cacheKey, userData, 5*time.Minute).Err()
		if err != nil {
			logger.Warn().
				Err(err).
				Str("user_id", userID.String()).
				Msg("failed to cache user data in redis")
			// continue anyway - cache failure is not critical
		}
	}

	return user, nil
}

func (s *UserService) InvalidateUserCache(ctx context.Context, userID pgtype.UUID) {
	cacheKey := "user:" + userID.String()
	err := s.redis.Del(ctx, cacheKey).Err()
	if err != nil {
		logger.Warn().
			Err(err).
			Str("user_id", userID.String()).
			Msg("failed to invalidate user cache")
	}
}

func (s *UserService) GetUserByEmail(ctx context.Context, email string) (*repository.User, error) {
	normalizedEmail := strings.ToLower(strings.TrimSpace(email))

	user, err := s.store.Queries.GetUserByEmail(ctx, normalizedEmail)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, failure.ErrUserNotFound
		}
		logger.Error().
			Err(err).
			Str("email", normalizedEmail).
			Msg("database error while fetching user")
		return nil, failure.ErrDatabaseError
	}
	return &user, nil
}

func (s *UserService) AuthenticateUser(ctx context.Context, email, password string) (*repository.User, error) {
	user, err := s.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, failure.ErrUserNotFound) {
			return nil, failure.ErrInvalidCredentials
		}
		return nil, err
	}

	if !user.IsActive.Bool {
		return nil, failure.ErrUserInactive
	}

	valid, err := s.hasher.VerifyPassword(password, user.PasswordHash)
	if err != nil {
		logger.Error().
			Err(err).
			Str("user_id", user.ID.String()).
			Msg("error verifying password")
		return nil, failure.ErrDatabaseError
	}

	if !valid {
		return nil, failure.ErrInvalidCredentials
	}

	return user, nil
}

func (s *UserService) LoginUser(ctx context.Context, req LoginRequest) (*LoginResponse, error) {
	user, err := s.AuthenticateUser(ctx, req.Email, req.Password)
	if err != nil {
		return nil, err
	}

	accessToken, err := auth.GenerateAccessToken(user.ID.String())
	if err != nil {
		logger.Error().
			Err(err).
			Str("user_id", user.ID.String()).
			Msg("failed to generate access token")
		return nil, failure.ErrTokenGeneration
	}

	refreshTokenExpiry := time.Now().Add(7 * 24 * time.Hour) // 7 days
	dbToken, err := s.store.Queries.CreateRefreshToken(ctx, repository.CreateRefreshTokenParams{
		UserID:      user.ID,
		DeviceInfo:  pgtype.Text{String: req.DeviceInfo, Valid: req.DeviceInfo != ""},
		ExpiresAt:   pgtype.Timestamptz{Time: refreshTokenExpiry, Valid: true},
		RotatedFrom: pgtype.UUID{Valid: false}, // no rotation for initial login
	})
	if err != nil {
		logger.Error().
			Err(err).
			Str("user_id", user.ID.String()).
			Msg("failed to create refresh token in database")
		return nil, failure.ErrDatabaseError
	}

	// generate refresh token jwt with the database token id as subject
	refreshToken, err := auth.GenerateRefreshToken(dbToken.ID.String())
	if err != nil {
		logger.Error().
			Err(err).
			Str("user_id", user.ID.String()).
			Msg("failed to generate refresh token JWT")
		return nil, failure.ErrTokenGeneration
	}

	err = s.createAuditLog(ctx, user.ID, "user_login", req.IP, req.UserAgent, map[string]any{
		"email":            user.Email,
		"refresh_token_id": dbToken.ID.String(),
	})
	if err != nil {
		logger.Warn().
			Err(err).
			Str("user_id", user.ID.String()).
			Msg("failed to create audit log for login")
	}

	accessClaims, _ := auth.ValidateAccessToken(accessToken)
	accessExpiresIn := int64(time.Until(accessClaims.ExpiresAt.Time).Seconds())
	refreshExpiresIn := int64(time.Until(refreshTokenExpiry).Seconds())

	logger.Info().
		Str("user_id", user.ID.String()).
		Str("email", user.Email).
		Str("refresh_token_id", dbToken.ID.String()).
		Msg("user logged in successfully")

	return &LoginResponse{
		UserID:           user.ID,
		Email:            user.Email,
		Permissions:      user.Permissions,
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		RefreshTokenID:   dbToken.ID,
		AccessExpiresIn:  accessExpiresIn,
		RefreshExpiresIn: refreshExpiresIn,
	}, nil
}

func (s *UserService) VerifyAccessToken(ctx context.Context, tokenString string) (*VerifyTokenResponse, error) {
	claims, err := auth.ValidateAccessToken(tokenString)
	if err != nil {
		if errors.Is(err, auth.ErrExpiredToken) {
			return nil, failure.ErrTokenExpired
		}
		return nil, failure.ErrInvalidToken
	}

	id, err := uuid.Parse(claims.UserID)
	userID := pgtype.UUID{Bytes: [16]byte(id), Valid: true}
	if err != nil {
		logger.Warn().
			Str("user_id", claims.UserID).
			Err(err).
			Msg("invalid user_id in token claims")
		return nil, failure.ErrInvalidToken
	}

	// check if token is blacklisted in redis (for logout)
	blacklistKey := "blacklist:access:" + tokenString
	exists, err := s.redis.Exists(ctx, blacklistKey).Result()
	if err != nil {
		logger.Warn().
			Err(err).
			Msg("redis error checking token blacklist")
	} else if exists > 0 {
		return nil, failure.ErrTokenRevoked
	}

	user, err := s.GetUserByIDWithCache(ctx, userID)
	if err != nil {
		return nil, err
	}

	if !user.IsActive.Bool {
		return nil, failure.ErrUserInactive
	}

	return &VerifyTokenResponse{
		Valid:       true,
		UserID:      user.ID,
		Email:       user.Email,
		Permissions: user.Permissions,
		ExpiresAt:   claims.ExpiresAt.Time,
	}, nil
}

func (s *UserService) RefreshAccessToken(ctx context.Context, req RefreshTokenRequest) (*RefreshTokenResponse, error) {
	refreshTokenIDStr, err := auth.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		if errors.Is(err, auth.ErrExpiredToken) {
			return nil, failure.ErrTokenExpired
		}
		return nil, failure.ErrInvalidToken
	}

	// parse the token id from jwt subject
	refreshTokenUUID, err := uuid.Parse(refreshTokenIDStr)
	refreshTokenID := pgtype.UUID{Bytes: [16]byte(refreshTokenUUID), Valid: true}
	if err != nil {
		logger.Warn().
			Str("token_id", refreshTokenIDStr).
			Err(err).
			Msg("invalid token_id in refresh token")
		return nil, failure.ErrInvalidToken
	}

	dbToken, err := s.store.Queries.GetRefreshToken(ctx, refreshTokenID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.Warn().
				Str("token_id", refreshTokenID.String()).
				Msg("refresh token not found or expired")
			return nil, failure.ErrInvalidToken
		}
		logger.Error().
			Err(err).
			Str("token_id", refreshTokenID.String()).
			Msg("database error while fetching refresh token")
		return nil, failure.ErrDatabaseError
	}

	user, err := s.GetUserByIDWithCache(ctx, dbToken.UserID)
	if err != nil {
		return nil, err
	}

	if !user.IsActive.Bool {
		return nil, failure.ErrUserInactive
	}

	// check if this token was already used (possible token reuse attack)
	// if rotated_from exists, it means this token was already rotated
	if dbToken.LastUsedAt.Valid {
		logger.Warn().
			Str("token_id", refreshTokenID.String()).
			Str("user_id", user.ID.String()).
			Msg("refresh token reuse detected - revoking token family")

		err = s.store.Queries.RevokeTokenFamily(ctx, refreshTokenID)
		if err != nil {
			logger.Error().Err(err).Msg("failed to revoke token family")
		}
		return nil, failure.ErrTokenRevoked
	}

	err = s.store.Queries.UpdateRefreshTokenLastUsed(ctx, refreshTokenID)
	if err != nil {
		logger.Error().
			Err(err).
			Str("token_id", refreshTokenID.String()).
			Msg("failed to update refresh token last used")
	}

	accessToken, err := auth.GenerateAccessToken(user.ID.String())
	if err != nil {
		logger.Error().
			Err(err).
			Str("user_id", user.ID.String()).
			Msg("failed to generate new access token")
		return nil, failure.ErrTokenGeneration
	}

	refreshTokenExpiry := time.Now().Add(7 * 24 * time.Hour) // 7 days
	newDBToken, err := s.store.Queries.CreateRefreshToken(ctx, repository.CreateRefreshTokenParams{
		UserID:      user.ID,
		DeviceInfo:  pgtype.Text{String: req.DeviceInfo, Valid: req.DeviceInfo != ""},
		ExpiresAt:   pgtype.Timestamptz{Time: refreshTokenExpiry, Valid: true},
		RotatedFrom: refreshTokenID, // link to old token
	})
	if err != nil {
		logger.Error().
			Err(err).
			Str("user_id", user.ID.String()).
			Msg("failed to create new refresh token in database")
		return nil, failure.ErrDatabaseError
	}

	newRefreshToken, err := auth.GenerateRefreshToken(newDBToken.ID.String())
	if err != nil {
		logger.Error().
			Err(err).
			Str("user_id", user.ID.String()).
			Msg("failed to generate new refresh token JWT")
		return nil, failure.ErrTokenGeneration
	}

	accessClaims, _ := auth.ValidateAccessToken(accessToken)
	accessExpiresIn := int64(time.Until(accessClaims.ExpiresAt.Time).Seconds())
	refreshExpiresIn := int64(time.Until(refreshTokenExpiry).Seconds())

	logger.Info().
		Str("user_id", user.ID.String()).
		Str("old_token_id", refreshTokenID.String()).
		Str("new_token_id", newDBToken.ID.String()).
		Msg("tokens refreshed successfully with rotation")

	return &RefreshTokenResponse{
		AccessToken:      accessToken,
		RefreshToken:     newRefreshToken,
		RefreshTokenID:   newDBToken.ID,
		AccessExpiresIn:  accessExpiresIn,
		RefreshExpiresIn: refreshExpiresIn,
	}, nil
}

func (s *UserService) BlacklistAccessToken(ctx context.Context, tokenString string) error {
	claims, err := auth.ValidateAccessToken(tokenString)
	if err != nil {
		logger.Debug().
			Err(err).
			Msg("attempted to blacklist invalid token")
		return nil
	}

	ttl := time.Until(claims.ExpiresAt.Time)
	if ttl <= 0 {
		return nil
	}

	blacklistKey := "blacklist:access:" + tokenString
	err = s.redis.Set(ctx, blacklistKey, "revoked", ttl).Err()
	if err != nil {
		logger.Error().
			Err(err).
			Str("token_preview", tokenString[:20]+"...").
			Msg("failed to blacklist token in redis")
		return failure.ErrDatabaseError
	}

	logger.Info().
		Str("user_id", claims.UserID).
		Dur("ttl", ttl).
		Msg("access token blacklisted successfully")

	return nil
}

func (s *UserService) LogoutUser(ctx context.Context, accessToken string, userID pgtype.UUID, ip, userAgent string) error {
	if err := s.BlacklistAccessToken(ctx, accessToken); err != nil {
		return err
	}

	err := s.createAuditLog(ctx, userID, "user_logout", ip, userAgent, map[string]any{
		"reason": "user_initiated",
	})
	if err != nil {
		logger.Warn().
			Err(err).
			Str("user_id", userID.String()).
			Msg("failed to create audit log for logout")
	}

	logger.Info().
		Str("user_id", userID.String()).
		Msg("user logged out successfully")

	return nil
}

// todo: use for password reset
func (s *UserService) RevokeAllUserTokens(ctx context.Context, userID pgtype.UUID, reason string) error {
	err := s.store.Queries.RevokeAllUserTokens(ctx, userID)
	if err != nil {
		logger.Error().
			Err(err).
			Str("user_id", userID.String()).
			Msg("failed to revoke all user tokens in database")
		return failure.ErrDatabaseError
	}

	logger.Info().
		Str("user_id", userID.String()).
		Str("reason", reason).
		Msg("all user refresh tokens revoked in database")

	return nil
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

func (s *UserService) SendVerificationEmail(ctx context.Context, user *RegisterUserResponse) error {
	token := uuid.New().String()
	params := repository.CreateEmailVerificationTokenParams{
		UserID:    user.UserID,
		TokenHash: token,
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

	err = s.store.ExecTx(ctx, func(*repository.Queries) error {
		_, updateErr := s.
			store.
			Queries.
			UpdateUserPassword(ctx, repository.UpdateUserPasswordParams{
				ID:           user.ID,
				PasswordHash: passwordHash,
			})

		if updateErr != nil {
			logger.Error().
				Err(updateErr).
				Msg("failed to update password")
			return updateErr
		}

		invErr := s.store.Queries.MarkPasswordResetTokenUsed(ctx, token.ID)

		if invErr != nil {
			logger.Error().
				Err(invErr).
				Msg("failed to invalidate token")

			return invErr
		}

		if err := s.RevokeAllUserTokens(ctx, user.ID, "password reset"); err != nil {
			return err
		}

		s.InvalidateUserCache(ctx, user.ID)

		return nil
	})

	if err != nil {
		logger.Error().
			Err(err).
			Str("email", user.Email).
			Msg("password change transaction failed")
		return failure.ErrPasswordReset
	}

	// move to transaction?
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

	verificationToken, err := s.store.Queries.GetEmailVerificationTokenByHash(ctx, token)
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

	if err := s.store.Queries.MarkEmailVerificationTokenUsed(ctx, verificationToken.ID); err != nil {
		logger.Error().
			Err(err).
			Str("token_id", verificationToken.ID.String()).
			Msg("failed to mark email verification token as used")
		return failure.ErrDatabaseError
	}

	_, err = s.store.Queries.UpdateUser(ctx, repository.UpdateUserParams{
		ID:             verificationToken.UserID,
		EmailConfirmed: pgtype.Bool{Bool: true, Valid: true},
	})
	if err != nil {
		logger.Error().
			Err(err).
			Str("user_id", verificationToken.UserID.String()).
			Msg("failed to update user email_confirmed status")
		return failure.ErrDatabaseError
	}

	s.InvalidateUserCache(ctx, verificationToken.UserID)

	logger.Info().
		Str("user_id", verificationToken.UserID.String()).
		Msg("email verified successfully")

	return nil
}
