package authenticateuserusecase

import (
	"context"
	"errors"
	"goauth/internal/auth"
	"goauth/internal/failure"
	"goauth/internal/logger"
	"goauth/internal/store"
	"goauth/internal/store/pg/repository"
	getuserbyemailusecase "goauth/internal/usecase/get_user_by_email_use_case"

	"github.com/redis/go-redis/v9"
)

type Params struct {
	Store  *store.Store
	Redis  *redis.Client
	Hasher *auth.PasswordHasher
}

type Payload struct {
	Email, Password string
}

type AuthenticateUserUseCase struct {
	ctx context.Context

	*Params
	*Payload
}

func New(ctx context.Context, params *Params, payload *Payload) *AuthenticateUserUseCase {
	return &AuthenticateUserUseCase{ctx: ctx, Params: params, Payload: payload}
}

func (u *AuthenticateUserUseCase) Execute() (*repository.User, error) {
	user, err := getuserbyemailusecase.
		New(u.ctx, &getuserbyemailusecase.Params{Store: u.Store}, &getuserbyemailusecase.Payload{Email: u.Email}).
		Execute()

	var dummyHash string
	if err != nil {
		dummyHash = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$somehashvalue"
	} else {
		dummyHash = user.PasswordHash
	}

	valid, hashErr := u.Hasher.VerifyPassword(u.Password, dummyHash)

	if hashErr != nil {
		logger.Error().Err(hashErr).Msg("error verifying password")
		return nil, failure.ErrDatabaseError
	}

	if err != nil {
		if errors.Is(err, failure.ErrUserNotFound) {
			return nil, failure.ErrInvalidCredentials
		}
		logger.Error().Err(err).Msg("database error fetching user")
		return nil, failure.ErrDatabaseError
	}

	if !user.IsActive.Bool {
		return nil, failure.ErrUserInactive
	}

	if !valid {
		return nil, failure.ErrInvalidCredentials
	}

	return user, nil
}
