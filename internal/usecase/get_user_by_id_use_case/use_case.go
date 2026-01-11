package getuserbyidusecase

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"goauth/internal/constants"
	"goauth/internal/failure"
	"goauth/internal/logger"
	"goauth/internal/store"
	"goauth/internal/store/pg/repository"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/redis/go-redis/v9"
)

type Params struct {
	Store *store.Store
	Redis *redis.Client
}

type Payload struct {
	UserID pgtype.UUID
}

type GetUserByIdUseCase struct {
	*Params
	*Payload
	ctx context.Context
}

func New(ctx context.Context, params *Params, payload *Payload) *GetUserByIdUseCase {
	return &GetUserByIdUseCase{
		Params:  params,
		Payload: payload,
		ctx:     ctx,
	}
}

func (s *GetUserByIdUseCase) getUserByID(ctx context.Context, userID pgtype.UUID) (*repository.User, error) {
	user, err := s.Store.Queries.GetUserByID(ctx, userID)
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

func (u *GetUserByIdUseCase) Execute() (*repository.User, error) {
	userID := u.UserID
	cacheKey := fmt.Sprintf(constants.RedisKeyUserCache, u.UserID.String())

	cachedData, err := u.Redis.Get(u.ctx, cacheKey).Result()
	if err == nil && cachedData != "" {
		var user repository.User
		if err := json.Unmarshal([]byte(cachedData), &user); err == nil {
			logger.Debug().
				Str("user_id", userID.String()).
				Msg("user fetched from cache")
			return &user, nil
		}
	}

	user, err := u.getUserByID(u.ctx, userID)
	if err != nil {
		return nil, err
	}

	userData, err := json.Marshal(user)
	if err == nil {
		err = u.Redis.Set(u.ctx, cacheKey, userData, 5*time.Minute).Err()
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
