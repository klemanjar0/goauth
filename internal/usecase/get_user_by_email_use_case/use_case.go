package getuserbyemailusecase

import (
	"context"
	"database/sql"
	"errors"
	"goauth/internal/failure"
	"goauth/internal/logger"
	"goauth/internal/store"
	"goauth/internal/store/pg/repository"
	"strings"
)

type Params struct {
	Store *store.Store
}

type Payload struct {
	Email string
}

type GetUserByEmailUseCase struct {
	ctx context.Context
	*Params
	*Payload
}

func New(ctx context.Context, params *Params, payload *Payload) *GetUserByEmailUseCase {
	return &GetUserByEmailUseCase{ctx: ctx, Params: params, Payload: payload}
}

func (u *GetUserByEmailUseCase) Execute() (*repository.User, error) {
	normalizedEmail := strings.ToLower(strings.TrimSpace(u.Email))

	user, err := u.Store.Queries.GetUserByEmail(u.ctx, normalizedEmail)
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
