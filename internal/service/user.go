package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"time"

	"goauth/internal/failure"
	"goauth/internal/utility"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/sqlc-dev/pqtype"

	"goauth/internal/auth"
	"goauth/internal/logger"
	"goauth/internal/store/pg/repository"
)

const (
	defaultPermissions = 0 // No special permissions by default
)

type UserService struct {
	queries      *repository.Queries
	redis        *redis.Client
	hasher       *auth.PasswordHasher
	db           *sql.DB
	emailService *EmailService
}

type RefreshTokenRequest struct {
	RefreshToken string
	DeviceInfo   string
}

type RefreshTokenResponse struct {
	AccessToken      string
	RefreshToken     string
	RefreshTokenID   uuid.UUID
	AccessExpiresIn  int64 // seconds until access token expires
	RefreshExpiresIn int64 // seconds until refresh token expires
}

type LoginResponse struct {
	UserID           uuid.UUID
	Email            string
	Permissions      int64
	AccessToken      string
	RefreshToken     string
	RefreshTokenID   uuid.UUID
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
	UserID         uuid.UUID
	Email          string
	Permissions    int64
	IsActive       bool
	EmailConfirmed bool
	CreatedAt      time.Time
}

type VerifyTokenResponse struct {
	Valid       bool
	UserID      uuid.UUID
	Email       string
	Permissions int64
	ExpiresAt   time.Time
}

func NewUserService(db *sql.DB, redisClient *redis.Client, emailService *EmailService) *UserService {
	return &UserService{
		queries:      repository.New(db),
		redis:        redisClient,
		hasher:       auth.NewPasswordHasher(),
		db:           db,
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

	existingUser, err := s.queries.GetUserByEmail(ctx, email)
	if err == nil && existingUser.ID != uuid.Nil {
		logger.Warn().
			Str("email", email).
			Msg("attempted registration with existing email")

		_ = s.createAuditLog(ctx, uuid.Nil, "registration_failed_duplicate", req.IP, req.UserAgent, map[string]any{
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

	user, err := s.queries.CreateUser(ctx, repository.CreateUserParams{
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

func (s *UserService) GetUserByID(ctx context.Context, userID uuid.UUID) (*repository.User, error) {
	user, err := s.queries.GetUserByID(ctx, userID)
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

func (s *UserService) GetUserByIDWithCache(ctx context.Context, userID uuid.UUID) (*repository.User, error) {
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

func (s *UserService) InvalidateUserCache(ctx context.Context, userID uuid.UUID) {
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

	user, err := s.queries.GetUserByEmail(ctx, normalizedEmail)
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
	dbToken, err := s.queries.CreateRefreshToken(ctx, repository.CreateRefreshTokenParams{
		UserID:      uuid.NullUUID{UUID: user.ID, Valid: true},
		DeviceInfo:  sql.NullString{String: req.DeviceInfo, Valid: req.DeviceInfo != ""},
		ExpiresAt:   refreshTokenExpiry,
		RotatedFrom: uuid.NullUUID{Valid: false}, // no rotation for initial login
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

	userID, err := uuid.Parse(claims.UserID)
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
	refreshTokenID, err := uuid.Parse(refreshTokenIDStr)
	if err != nil {
		logger.Warn().
			Str("token_id", refreshTokenIDStr).
			Err(err).
			Msg("invalid token_id in refresh token")
		return nil, failure.ErrInvalidToken
	}

	dbToken, err := s.queries.GetRefreshToken(ctx, refreshTokenID)
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

	user, err := s.GetUserByID(ctx, dbToken.UserID.UUID)
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

		err = s.queries.RevokeTokenFamily(ctx, refreshTokenID)
		if err != nil {
			logger.Error().Err(err).Msg("failed to revoke token family")
		}
		return nil, failure.ErrTokenRevoked
	}

	err = s.queries.UpdateRefreshTokenLastUsed(ctx, refreshTokenID)
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
	newDBToken, err := s.queries.CreateRefreshToken(ctx, repository.CreateRefreshTokenParams{
		UserID:      uuid.NullUUID{UUID: user.ID, Valid: true},
		DeviceInfo:  sql.NullString{String: req.DeviceInfo, Valid: req.DeviceInfo != ""},
		ExpiresAt:   refreshTokenExpiry,
		RotatedFrom: uuid.NullUUID{UUID: refreshTokenID, Valid: true}, // link to old token
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

func (s *UserService) LogoutUser(ctx context.Context, accessToken string, userID uuid.UUID, ip, userAgent string) error {
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
func (s *UserService) RevokeAllUserTokens(ctx context.Context, userID uuid.UUID, reason string) error {
	err := s.queries.RevokeAllUserTokens(ctx, uuid.NullUUID{UUID: userID, Valid: true})
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

func (s *UserService) createAuditLog(ctx context.Context, userID uuid.UUID, eventType, ip, userAgent string, payload map[string]any) error {
	params := repository.CreateAuditLogParams{
		EventType: eventType,
	}

	if userID != uuid.Nil {
		params.UserID = uuid.NullUUID{UUID: userID, Valid: true}
	}

	if ip != "" {
		ipAddr := net.ParseIP(ip)
		if ipAddr != nil {
			params.Ip = pqtype.Inet{
				IPNet: net.IPNet{
					IP:   ipAddr,
					Mask: ipAddr.DefaultMask(),
				},
				Valid: true,
			}
		}
	}

	if userAgent != "" {
		params.Ua = sql.NullString{String: userAgent, Valid: true}
	}

	if payload != nil {
		jsonBytes, err := json.Marshal(payload)
		if err == nil {
			params.Payload = pqtype.NullRawMessage{
				RawMessage: jsonBytes,
				Valid:      true,
			}
		}
	}

	_, err := s.queries.CreateAuditLog(ctx, params)
	return err
}

func (s *UserService) SendVerificationEmail(ctx context.Context, user *RegisterUserResponse) error {
	token := uuid.New().String()
	params := repository.CreateEmailVerificationTokenParams{
		UserID:    uuid.NullUUID{UUID: user.UserID, Valid: true},
		TokenHash: token,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	_, err := s.queries.CreateEmailVerificationToken(ctx, params)
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

func (s *UserService) VerifyEmail(ctx context.Context, token string) error {
	if token == "" {
		return failure.ErrInvalidToken
	}

	verificationToken, err := s.queries.GetEmailVerificationTokenByHash(ctx, token)
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

	if err := s.queries.MarkEmailVerificationTokenUsed(ctx, verificationToken.ID); err != nil {
		logger.Error().
			Err(err).
			Str("token_id", verificationToken.ID.String()).
			Msg("failed to mark email verification token as used")
		return failure.ErrDatabaseError
	}

	_, err = s.queries.UpdateUser(ctx, repository.UpdateUserParams{
		ID:             verificationToken.UserID.UUID,
		EmailConfirmed: sql.NullBool{Bool: true, Valid: true},
	})
	if err != nil {
		logger.Error().
			Err(err).
			Str("user_id", verificationToken.UserID.UUID.String()).
			Msg("failed to update user email_confirmed status")
		return failure.ErrDatabaseError
	}

	s.InvalidateUserCache(ctx, verificationToken.UserID.UUID)

	logger.Info().
		Str("user_id", verificationToken.UserID.UUID.String()).
		Msg("email verified successfully")

	return nil
}
