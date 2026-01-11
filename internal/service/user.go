package service

import (
	"context"

	"goauth/internal/auth"
	"goauth/internal/kafka"
	"goauth/internal/store"
	"goauth/internal/store/pg/repository"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/redis/go-redis/v9"

	authenticateuserusecase "goauth/internal/usecase/authenticate_user_use_case"
	getuserbyemailusecase "goauth/internal/usecase/get_user_by_email_use_case"
	getuserbyidusecase "goauth/internal/usecase/get_user_by_id_use_case"
	invalidateusercacheusecase "goauth/internal/usecase/invalidate_user_cache_use_case"
	loginusecase "goauth/internal/usecase/login_use_case"
	logoutusecase "goauth/internal/usecase/logout_use_case"
	refreshaccesstokenusecase "goauth/internal/usecase/refresh_access_token_use_case"
	registerusecase "goauth/internal/usecase/register_use_case"
	resetpasswordusecase "goauth/internal/usecase/reset_password_use_case"
	sendpasswordresetemailusecase "goauth/internal/usecase/send_password_reset_email_use_case"
	sendverificationemailusecase "goauth/internal/usecase/send_verification_email_use_case"
	verifyaccesstokenusecase "goauth/internal/usecase/verify_access_token_use_case"
	verifyemailusecase "goauth/internal/usecase/verify_email_use_case"
)

type UserService struct {
	store    *store.Store
	redis    *redis.Client
	hasher   *auth.PasswordHasher
	producer *kafka.Producer
}

func NewUserService(store *store.Store, redisClient *redis.Client, producer *kafka.Producer) *UserService {
	return &UserService{
		store:    store,
		redis:    redisClient,
		hasher:   auth.NewPasswordHasher(),
		producer: producer,
	}
}

func (s *UserService) RegisterUser(
	ctx context.Context,
	req registerusecase.Payload,
) (*registerusecase.Response, error) {
	return registerusecase.New(
		ctx,
		&registerusecase.Params{
			Store:       s.store,
			RedisClient: s.redis,
			Hasher:      s.hasher,
		},
		&req,
	).Execute()
}

func (s *UserService) GetUserByIDWithCache(ctx context.Context, userID pgtype.UUID) (*repository.User, error) {
	return getuserbyidusecase.New(ctx, &getuserbyidusecase.Params{
		Store: s.store,
		Redis: s.redis,
	}, &getuserbyidusecase.Payload{UserID: userID}).Execute()
}

func (s *UserService) InvalidateUserCache(ctx context.Context, userID pgtype.UUID) {
	invalidateusercacheusecase.
		New(ctx,
			&invalidateusercacheusecase.Params{
				Redis: s.redis,
			},
			&invalidateusercacheusecase.Payload{
				UserID: userID,
			}).
		Execute()
}

func (s *UserService) GetUserByEmail(ctx context.Context, email string) (*repository.User, error) {
	return getuserbyemailusecase.
		New(ctx, &getuserbyemailusecase.Params{Store: s.store}, &getuserbyemailusecase.Payload{Email: email}).
		Execute()
}

func (s *UserService) AuthenticateUser(ctx context.Context, email, password string) (*repository.User, error) {
	return authenticateuserusecase.
		New(ctx,
			&authenticateuserusecase.Params{Store: s.store, Redis: s.redis, Hasher: s.hasher},
			&authenticateuserusecase.Payload{Email: email, Password: password},
		).
		Execute()
}

func (s *UserService) VerifyAccessToken(ctx context.Context, req verifyaccesstokenusecase.Payload) (*verifyaccesstokenusecase.Response, error) {
	return verifyaccesstokenusecase.New(
		ctx,
		&verifyaccesstokenusecase.Params{
			Store: s.store,
			Redis: s.redis,
		},
		&req,
	).Execute()
}

func (s *UserService) LoginUser(ctx context.Context, req loginusecase.Payload) (*loginusecase.Response, error) {
	return loginusecase.New(
		ctx,
		&loginusecase.Params{
			Store:  s.store,
			Redis:  s.redis,
			Hasher: s.hasher,
		},
		&req,
	).Execute()
}

func (s *UserService) RefreshAccessToken(ctx context.Context, req refreshaccesstokenusecase.Payload) (*refreshaccesstokenusecase.Response, error) {
	return refreshaccesstokenusecase.
		New(
			ctx,
			&refreshaccesstokenusecase.Params{
				Store: s.store,
				Redis: s.redis,
			},
			&req,
		).Execute()
}

func (s *UserService) LogoutUser(ctx context.Context, accessToken string, userID pgtype.UUID, ip, userAgent string) error {
	return logoutusecase.New(
		ctx,
		&logoutusecase.Params{Store: s.store, Redis: s.redis},
		&logoutusecase.Payload{AccessToken: accessToken, UserID: userID, IP: ip, UserAgent: userAgent},
	).Execute()
}

func (s *UserService) SendVerificationEmail(ctx context.Context, user *registerusecase.Response) error {
	return sendverificationemailusecase.New(
		ctx,
		&sendverificationemailusecase.Params{Store: s.store, Producer: s.producer},
		&sendverificationemailusecase.Payload{User: user},
	).Execute()
}

func (s *UserService) SendPasswordResetEmail(ctx context.Context, email string) error {
	return sendpasswordresetemailusecase.New(
		ctx,
		&sendpasswordresetemailusecase.Params{Store: s.store, Producer: s.producer},
		&sendpasswordresetemailusecase.Payload{Email: email},
	).Execute()
}

func (s *UserService) ResetPassword(ctx context.Context, payload resetpasswordusecase.Payload) error {
	return resetpasswordusecase.New(
		ctx,
		&resetpasswordusecase.Params{Store: s.store, Redis: s.redis, Hasher: s.hasher},
		&payload,
	).Execute()
}

func (s *UserService) VerifyEmail(ctx context.Context, token string) error {
	return verifyemailusecase.New(
		ctx,
		&verifyemailusecase.Params{Store: s.store, Redis: s.redis},
		&verifyemailusecase.Payload{Token: token},
	).Execute()
}
