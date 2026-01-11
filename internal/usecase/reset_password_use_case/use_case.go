package resetpasswordusecase

import (
	"context"
	"goauth/internal/auth"
	"goauth/internal/failure"
	"goauth/internal/logger"
	"goauth/internal/store"
	"goauth/internal/store/pg/repository"
	createauditlogusecase "goauth/internal/usecase/create_audit_log_use_case"
	getuserbyidusecase "goauth/internal/usecase/get_user_by_id_use_case"
	invalidateusercacheusecase "goauth/internal/usecase/invalidate_user_cache_use_case"
	"goauth/internal/utility"

	"github.com/redis/go-redis/v9"
)

type Params struct {
	Store  *store.Store
	Redis  *redis.Client
	Hasher *auth.PasswordHasher
}

type Payload struct {
	Token       string
	NewPassword string
	IP          string
	UserAgent   string
}

type ResetPasswordUseCase struct {
	ctx context.Context

	*Params
	*Payload
}

func New(ctx context.Context, params *Params, payload *Payload) *ResetPasswordUseCase {
	return &ResetPasswordUseCase{ctx: ctx, Params: params, Payload: payload}
}

func (u *ResetPasswordUseCase) Execute() error {
	var user *repository.User
	var err error

	tokenHash := auth.HashToken256(u.Token)

	var token repository.PasswordResetToken
	token, err = u.Store.Queries.GetPasswordResetTokenByHash(u.ctx, tokenHash)

	if err != nil {
		logger.Error().
			Err(err).
			Msg("token is not found")
		return failure.ErrTokenInvalid
	}

	user, err = getuserbyidusecase.New(
		u.ctx,
		&getuserbyidusecase.Params{Store: u.Store, Redis: u.Redis},
		&getuserbyidusecase.Payload{UserID: token.UserID},
	).Execute()

	if err != nil {
		logger.Error().
			Err(err).
			Str("uuid", token.UserID.String()).
			Msg("failed to get user data with token")
		return failure.ErrDatabaseError
	}

	if err := utility.ValidatePassword(u.NewPassword); err != nil {
		logger.Warn().
			Str("email", user.Email).
			Err(err).
			Msg("weak password during registration")
		return failure.ErrPasswordTooWeak
	}

	passwordHash, err := u.Hasher.HashPassword(u.NewPassword)
	if err != nil {
		logger.Error().
			Err(err).
			Str("email", user.Email).
			Msg("failed to hash password")
		return failure.ErrPasswordHashError
	}

	err = u.Store.ExecTx(u.ctx, func(tx *repository.Queries) error {
		_, updateErr :=
			tx.UpdateUserPassword(u.ctx, repository.UpdateUserPasswordParams{
				ID:           user.ID,
				PasswordHash: passwordHash,
			})

		if updateErr != nil {
			logger.Error().
				Err(updateErr).
				Msg("failed to update password")
			return updateErr
		}

		invErr := tx.MarkPasswordResetTokenUsed(u.ctx, token.ID)

		if invErr != nil {
			logger.Error().
				Err(invErr).
				Msg("failed to invalidate token")

			return invErr
		}

		if err := tx.RevokeAllUserTokens(u.ctx, user.ID); err != nil {
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

	invalidateusercacheusecase.New(
		u.ctx,
		&invalidateusercacheusecase.Params{Redis: u.Redis},
		&invalidateusercacheusecase.Payload{UserID: user.ID},
	).Execute()

	err = createauditlogusecase.New(
		u.ctx,
		&createauditlogusecase.Params{
			Store: u.Store,
		},
		&createauditlogusecase.Payload{
			UserID:    user.ID,
			EventType: "user_password_reset",
			Ip:        u.IP,
			UserAgent: u.UserAgent,
			Payload: map[string]any{
				"reason": "user_initiated",
			},
		}).
		Execute()

	if err != nil {
		logger.Error().
			Err(err).
			Msg("createAuditLog failed")
	}

	return nil
}
