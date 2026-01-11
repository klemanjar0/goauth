package handler

import (
	"context"
	"goauth/internal/constants"
	"goauth/internal/store"
	getuserbyidusecase "goauth/internal/usecase/get_user_by_id_use_case"
	refreshaccesstokenusecase "goauth/internal/usecase/refresh_access_token_use_case"
	revokeusertokensusecase "goauth/internal/usecase/revoke_user_tokens_use_case"
	verifyaccesstokenusecase "goauth/internal/usecase/verify_access_token_use_case"
	"goauth/pkg/authpb"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type AuthHandler struct {
	authpb.UnimplementedAuthServiceServer
	store *store.Store
	redis *redis.Client
}

func NewAuthHandler(
	store *store.Store,
	redis *redis.Client,
) *AuthHandler {
	return &AuthHandler{
		store: store,
		redis: redis,
	}
}

func (h *AuthHandler) ValidateToken(ctx context.Context, req *authpb.ValidateTokenRequest) (*authpb.ValidateTokenResponse, error) {
	if req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}

	claims, err := verifyaccesstokenusecase.New(ctx,
		&verifyaccesstokenusecase.Params{
			Store: h.store,
			Redis: h.redis,
		},
		&verifyaccesstokenusecase.Payload{
			Token: req.Token,
		},
	).Execute()

	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid or expired token")
	}

	return &authpb.ValidateTokenResponse{
		Valid:       true,
		UserId:      claims.UserID.String(),
		Email:       claims.Email,
		Permissions: claims.Permissions,
	}, nil
}

func (h *AuthHandler) GetUserFromToken(ctx context.Context, req *authpb.GetUserFromTokenRequest) (*authpb.GetUserFromTokenResponse, error) {
	if req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}

	claims, err := verifyaccesstokenusecase.New(ctx,
		&verifyaccesstokenusecase.Params{
			Store: h.store,
			Redis: h.redis,
		},
		&verifyaccesstokenusecase.Payload{
			Token: req.Token,
		},
	).Execute()

	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid or expired token")
	}

	user, err := getuserbyidusecase.New(ctx, &getuserbyidusecase.Params{
		Store: h.store,
		Redis: h.redis,
	}, &getuserbyidusecase.Payload{UserID: claims.UserID}).Execute()

	if err != nil {
		return nil, status.Error(codes.NotFound, "user not found")
	}

	return &authpb.GetUserFromTokenResponse{
		User: &authpb.User{
			Id:             user.ID.String(),
			Email:          user.Email,
			Permissions:    claims.Permissions,
			IsActive:       user.IsActive.Bool,
			EmailConfirmed: user.EmailConfirmed.Bool,
			CreatedAt:      timestamppb.New(user.CreatedAt.Time),
		},
	}, nil
}

func (h *AuthHandler) CheckPermission(ctx context.Context, req *authpb.CheckPermissionRequest) (*authpb.CheckPermissionResponse, error) {
	if req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}
	if req.RequiredPermission == 0 {
		return nil, status.Error(codes.InvalidArgument, "required_permission is required")
	}

	claims, err := verifyaccesstokenusecase.New(ctx,
		&verifyaccesstokenusecase.Params{
			Store: h.store,
			Redis: h.redis,
		},
		&verifyaccesstokenusecase.Payload{
			Token: req.Token,
		},
	).Execute()

	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid or expired token")
	}

	hasPermission := constants.HasPermission(constants.Permission(claims.Permissions), constants.Permission(req.RequiredPermission))

	if !hasPermission {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions")
	}

	return &authpb.CheckPermissionResponse{
		HasPermission: true,
	}, nil
}

func (h *AuthHandler) RefreshToken(ctx context.Context, req *authpb.RefreshTokenRequest) (*authpb.RefreshTokenResponse, error) {
	if req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh_token is required")
	}

	deviceInfo := ""
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if devices := md.Get("device-info"); len(devices) > 0 {
			deviceInfo = devices[0]
		}
	}

	resp, err := refreshaccesstokenusecase.
		New(ctx,
			&refreshaccesstokenusecase.Params{Store: h.store, Redis: h.redis},
			&refreshaccesstokenusecase.Payload{
				RefreshToken: req.RefreshToken,
				DeviceInfo:   deviceInfo,
			},
		).Execute()

	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid or expired refresh token")
	}

	return &authpb.RefreshTokenResponse{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		ExpiresIn:    resp.AccessExpiresIn,
	}, nil
}

func (h *AuthHandler) RevokeUserTokens(ctx context.Context, req *authpb.RevokeUserTokensRequest) (*authpb.RevokeUserTokensResponse, error) {
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	id, err := uuid.Parse(req.UserId)
	userId := pgtype.UUID{Bytes: [16]byte(id), Valid: true}
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user_id format")
	}

	err = revokeusertokensusecase.
		New(ctx,
			&revokeusertokensusecase.Params{Store: h.store},
			&revokeusertokensusecase.Payload{UserID: userId, Reason: "grpc_initiated"},
		).
		Execute()

	if err != nil {
		return nil, err
	}

	return &authpb.RevokeUserTokensResponse{
		Success: true,
	}, nil
}
