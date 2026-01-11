package loginusecase

import (
	"context"
	"goauth/internal/auth"
	"goauth/internal/failure"
	"goauth/internal/logger"
	"goauth/internal/store"
	"goauth/internal/store/pg/repository"
	authenticateuserusecase "goauth/internal/usecase/authenticate_user_use_case"
	createauditlogusecase "goauth/internal/usecase/create_audit_log_use_case"
	isaccountlockedusecase "goauth/internal/usecase/is_account_locked_use_case"
	recordfailedloginusecase "goauth/internal/usecase/record_failed_login_use_case"
	resetfailedloginsusecase "goauth/internal/usecase/reset_failed_logins_use_case"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/redis/go-redis/v9"
)

type Params struct {
	Store  *store.Store
	Redis  *redis.Client
	Hasher *auth.PasswordHasher
}

type Payload struct {
	Email      string
	Password   string
	DeviceInfo string
	IP         string
	UserAgent  string
}

type Response struct {
	UserID           pgtype.UUID
	Email            string
	Permissions      int64
	AccessToken      string
	RefreshToken     string
	RefreshTokenID   pgtype.UUID
	AccessExpiresIn  int64
	RefreshExpiresIn int64
}

type LoginUseCase struct {
	ctx context.Context

	*Params
	*Payload
}

func New(ctx context.Context, params *Params, payload *Payload) *LoginUseCase {
	return &LoginUseCase{ctx: ctx, Params: params, Payload: payload}
}

func (u *LoginUseCase) Execute() (*Response, error) {
	email := strings.ToLower(strings.TrimSpace(u.Email))

	isAccountLocked := isaccountlockedusecase.
		New(
			u.ctx,
			&isaccountlockedusecase.Params{Redis: u.Redis},
			&isaccountlockedusecase.Payload{Email: email},
		).
		Execute()

	if isAccountLocked {
		logger.Warn().Str("email", email).Msg("login attempt on locked account")
		return nil, failure.ErrInvalidCredentials
	}

	user, err := authenticateuserusecase.New(
		u.ctx,
		&authenticateuserusecase.Params{
			Store:  u.Store,
			Redis:  u.Redis,
			Hasher: u.Hasher,
		},
		&authenticateuserusecase.Payload{
			Email:    u.Email,
			Password: u.Password,
		},
	).Execute()

	if err != nil {
		_ = recordfailedloginusecase.New(u.ctx,
			&recordfailedloginusecase.Params{
				Redis: u.Redis,
			},
			&recordfailedloginusecase.Payload{Email: u.Email},
		).Execute()
		return nil, err
	}

	resetfailedloginsusecase.New(
		u.ctx,
		&resetfailedloginsusecase.Params{
			Redis: u.Redis,
		},
		&resetfailedloginsusecase.Payload{
			Email: u.Email,
		},
	).Execute()

	accessToken, err := auth.GenerateAccessToken(user.ID.String())
	if err != nil {
		logger.Error().
			Err(err).
			Str("user_id", user.ID.String()).
			Msg("failed to generate access token")
		return nil, failure.ErrTokenGeneration
	}

	refreshTokenExpiry := time.Now().Add(7 * 24 * time.Hour) // 7 days
	dbToken, err := u.Store.Queries.CreateRefreshToken(u.ctx, repository.CreateRefreshTokenParams{
		UserID:      user.ID,
		DeviceInfo:  pgtype.Text{String: u.DeviceInfo, Valid: u.DeviceInfo != ""},
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

	err = createauditlogusecase.New(
		u.ctx,
		&createauditlogusecase.Params{
			Store: u.Store,
		},
		&createauditlogusecase.Payload{
			UserID:    user.ID,
			EventType: "user_login",
			Ip:        u.IP,
			UserAgent: u.UserAgent,
			Payload: map[string]any{
				"email":            user.Email,
				"refresh_token_id": dbToken.ID.String(),
			},
		}).
		Execute()

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

	return &Response{
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
