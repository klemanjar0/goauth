package handler

import (
	"context"
	"goauth/internal/constants"
	"goauth/internal/service"
	"goauth/pkg/authpb"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type AuthHandler struct {
	authpb.UnimplementedAuthServiceServer
	userService *service.UserService
}

func NewAuthHandler(userService *service.UserService) *AuthHandler {
	return &AuthHandler{
		userService: userService,
	}
}

func (h *AuthHandler) ValidateToken(ctx context.Context, req *authpb.ValidateTokenRequest) (*authpb.ValidateTokenResponse, error) {
	if req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}

	claims, err := h.userService.VerifyAccessToken(ctx, req.Token)
	if err != nil {
		// Return proper gRPC error instead of error in response
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

	claims, err := h.userService.VerifyAccessToken(ctx, req.Token)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid or expired token")
	}

	user, err := h.userService.GetUserByID(ctx, claims.UserID)
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

	claims, err := h.userService.VerifyAccessToken(ctx, req.Token)
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

	// Extract device info from metadata if available
	deviceInfo := ""
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if devices := md.Get("device-info"); len(devices) > 0 {
			deviceInfo = devices[0]
		}
	}

	payload := struct {
		RefreshToken string
		DeviceInfo   string
	}{
		RefreshToken: req.RefreshToken,
		DeviceInfo:   deviceInfo,
	}

	resp, err := h.userService.RefreshAccessToken(ctx, payload)
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
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user_id format")
	}

	err = h.userService.RevokeAllUserTokens(ctx, id, "")
	if err != nil {
		// Error will be mapped by errorMappingInterceptor
		return nil, err
	}

	return &authpb.RevokeUserTokensResponse{
		Success: true,
	}, nil
}
