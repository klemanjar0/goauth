package logoutusecase

import (
	"context"
	"goauth/internal/logger"
	"goauth/internal/store"
	blacklistaccesstokenusecase "goauth/internal/usecase/blacklist_access_token_use_case"
	createauditlogusecase "goauth/internal/usecase/create_audit_log_use_case"
	invalidateusercacheusecase "goauth/internal/usecase/invalidate_user_cache_use_case"
	revokeusertokensusecase "goauth/internal/usecase/revoke_user_tokens_use_case"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/redis/go-redis/v9"
)

type Params struct {
	Store *store.Store
	Redis *redis.Client
}
type Payload struct {
	AccessToken   string
	UserID        pgtype.UUID
	IP, UserAgent string
}

type LogoutUseCase struct {
	ctx context.Context

	*Params
	*Payload
}

func New(ctx context.Context, params *Params, payload *Payload) *LogoutUseCase {
	return &LogoutUseCase{ctx: ctx, Params: params, Payload: payload}
}

func (u *LogoutUseCase) Execute() error {
	if err := blacklistaccesstokenusecase.New(u.ctx,
		&blacklistaccesstokenusecase.Params{Redis: u.Redis},
		&blacklistaccesstokenusecase.Payload{Token: u.AccessToken},
	).Execute(); err != nil {
		return err
	}

	if err := revokeusertokensusecase.New(u.ctx,
		&revokeusertokensusecase.Params{Store: u.Store},
		&revokeusertokensusecase.Payload{UserID: u.UserID, Reason: "user_logout"},
	).Execute(); err != nil {
		logger.Error().Err(err).Str("user_id", u.UserID.String()).Msg("failed to revoke refresh tokens on logout")
		return err
	}

	if err := invalidateusercacheusecase.New(u.ctx,
		&invalidateusercacheusecase.Params{Redis: u.Redis},
		&invalidateusercacheusecase.Payload{UserID: u.UserID},
	).Execute(); err != nil {
		return err
	}

	err := createauditlogusecase.New(
		u.ctx,
		&createauditlogusecase.Params{
			Store: u.Store,
		},
		&createauditlogusecase.Payload{
			UserID:    u.UserID,
			EventType: "user_logout",
			Ip:        u.IP,
			UserAgent: u.UserAgent,
			Payload: map[string]any{
				"reason": "user_initiated",
			},
		}).
		Execute()

	if err != nil {
		logger.Warn().
			Err(err).
			Str("user_id", u.UserID.String()).
			Msg("failed to create audit log for logout")
	}

	logger.Info().
		Str("user_id", u.UserID.String()).
		Msg("user logged out successfully")

	return nil
}
