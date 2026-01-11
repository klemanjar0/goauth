package registerusecase

import (
	"context"
	"database/sql"
	"errors"
	"goauth/internal/auth"
	"goauth/internal/failure"
	"goauth/internal/logger"
	"goauth/internal/store"
	"goauth/internal/store/pg/repository"
	createauditlogusecase "goauth/internal/usecase/create_audit_log_use_case"
	"goauth/internal/utility"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/redis/go-redis/v9"
)

const (
	defaultPermissions = 0 // No special permissions by default
)

type Params struct {
	Store       *store.Store
	RedisClient *redis.Client
	Hasher      *auth.PasswordHasher
}

type Payload struct {
	Email       string
	Password    string
	Permissions int64
	IP          string
	UserAgent   string
}

type Response struct {
	UserID         pgtype.UUID
	Email          string
	Permissions    int64
	IsActive       bool
	EmailConfirmed bool
	CreatedAt      time.Time
}

type RegisterUseCase struct {
	*Params
	*Payload

	ctx context.Context
}

func New(
	ctx context.Context,
	params *Params,
	payload *Payload,
) *RegisterUseCase {
	return &RegisterUseCase{
		Params:  params,
		Payload: payload,
		ctx:     ctx,
	}
}

func (u *RegisterUseCase) Execute() (*Response, error) {
	req := u.Payload
	ctx := u.ctx

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

	existingUser, err := u.Store.Queries.GetUserByEmail(ctx, email)
	if err == nil && existingUser.ID.Valid {
		logger.Warn().
			Str("email", email).
			Msg("attempted registration with existing email")

		_ = createauditlogusecase.New(ctx, &createauditlogusecase.Params{
			Store: u.Store,
		}, &createauditlogusecase.Payload{
			UserID:    pgtype.UUID{Valid: false},
			EventType: "registration_failed_duplicate",
			Ip:        req.IP,
			UserAgent: req.UserAgent,
			Payload: map[string]any{
				"email":  email,
				"reason": "duplicate_email",
			},
		}).Execute()

		return nil, failure.ErrUserAlreadyExists
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		logger.Error().
			Err(err).
			Str("email", email).
			Msg("database error while checking existing user")
		return nil, failure.ErrDatabaseError
	}

	passwordHash, err := u.Hasher.HashPassword(req.Password)
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

	user, err := u.Store.Queries.CreateUser(ctx, repository.CreateUserParams{
		Email:        email,
		PasswordHash: passwordHash,
		Permissions:  permissions,
	})
	if err != nil {
		if isUniqueViolation(err) {
			logger.Warn().Str("email", email).Msg("duplicate registration attempt")
			return nil, failure.ErrUserAlreadyExists
		}

		logger.Error().
			Err(err).
			Str("email", email).
			Msg("failed to create user in database")
		return nil, failure.ErrDatabaseError
	}

	err = createauditlogusecase.New(ctx, &createauditlogusecase.Params{
		Store: u.Store,
	}, &createauditlogusecase.Payload{
		UserID:    user.ID,
		EventType: "user_registered",
		Ip:        req.IP,
		UserAgent: req.UserAgent,
		Payload: map[string]any{
			"email":       email,
			"permissions": permissions,
		},
	}).Execute()

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

	return &Response{
		UserID:         user.ID,
		Email:          user.Email,
		Permissions:    user.Permissions,
		IsActive:       user.IsActive.Bool,
		EmailConfirmed: user.EmailConfirmed.Bool,
		CreatedAt:      user.CreatedAt.Time,
	}, nil
}

func isUniqueViolation(err error) bool {
	// Check for PostgreSQL unique constraint violation (error code 23505)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}
