package revokeusertokensusecase

import (
	"context"
	"goauth/internal/failure"
	"goauth/internal/logger"
	"goauth/internal/store"

	"github.com/jackc/pgx/v5/pgtype"
)

type Params struct {
	Store *store.Store
}
type Payload struct {
	UserID pgtype.UUID
	Reason string
}

type RevokeAllUserTokensUseCase struct {
	ctx context.Context

	*Params
	*Payload
}

func New(ctx context.Context, params *Params, payload *Payload) *RevokeAllUserTokensUseCase {
	return &RevokeAllUserTokensUseCase{ctx: ctx, Params: params, Payload: payload}
}

func (u *RevokeAllUserTokensUseCase) Execute() error {
	err := u.Store.Queries.RevokeAllUserTokens(u.ctx, u.UserID)
	if err != nil {
		logger.Error().
			Err(err).
			Str("user_id", u.UserID.String()).
			Msg("failed to revoke all user tokens in database")
		return failure.ErrDatabaseError
	}

	logger.Info().
		Str("user_id", u.UserID.String()).
		Str("reason", u.Reason).
		Msg("all user refresh tokens revoked in database")

	return nil
}
