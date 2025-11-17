package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"goauth/internal"
	"goauth/internal/failure"
	"goauth/internal/logger"
	"goauth/internal/service"
	"goauth/internal/utility"
)

type UserHandler struct {
	userService *service.UserService
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type VerifyTokenRequest struct {
	Token string `json:"token"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func NewUserHandler(userService *service.UserService) *UserHandler {
	return &UserHandler{
		userService: userService,
	}
}

func (u *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Warn().
			Err(err).
			Str("path", r.URL.Path).
			Msg("failed to decode registration request")

		internal.Respond(w).BadRequest(err)
		return
	}
	defer r.Body.Close()

	clientIP := utility.GetClientIP(r)
	userAgent := r.UserAgent()

	ctx := r.Context()
	result, err := u.userService.RegisterUser(ctx, service.RegisterUserRequest{
		Email:       req.Email,
		Password:    req.Password,
		Permissions: 0,
		IP:          clientIP,
		UserAgent:   userAgent,
	})

	if err != nil {
		switch {
		case errors.Is(err, failure.ErrUserAlreadyExists):
			internal.
				Respond(w).
				Status(http.StatusConflict).
				Error(err).Message(failure.ErrUserAlreadyExists.Error()).
				Send()
		case errors.Is(err, failure.ErrInvalidEmail):
			internal.
				Respond(w).
				Status(http.StatusBadRequest).
				Error(err).Message(failure.ErrInvalidEmail.Error()).
				Send()
		case errors.Is(err, failure.ErrPasswordTooWeak):
			internal.
				Respond(w).
				Status(http.StatusBadRequest).
				Error(err).Message(failure.ErrPasswordTooWeak.Error()).
				Send()
		case errors.Is(err, failure.ErrDatabaseError):
			logger.Error().Err(err).Msg("database error during registration")
			internal.
				Respond(w).
				Status(http.StatusInternalServerError).
				Error(err).Message(failure.ErrServer.Error()).
				Send()
		default:
			logger.Error().Err(err).Msg("unexpected error during registration")
			internal.
				Respond(w).
				Status(http.StatusInternalServerError).
				Error(err).Message(failure.ErrServer.Error()).
				Send()
		}
		return
	}

	response := map[string]interface{}{
		"success": true,
		"data": map[string]interface{}{
			"user_id":         result.UserID,
			"email":           result.Email,
			"email_confirmed": result.EmailConfirmed,
			"is_active":       result.IsActive,
			"created_at":      result.CreatedAt,
		},
		"message": "user registered successfully",
	}

	internal.Respond(w).
		Status(http.StatusCreated).
		Header("X-Request-ID", utility.GetRequestID(r)).
		Json(response).
		Send()
}

func (h *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		internal.
			Respond(w).
			BadRequest(errors.New("invalid request body"))
		return
	}
	defer r.Body.Close()

	clientIP := utility.GetClientIP(r)
	userAgent := r.UserAgent()

	ctx := r.Context()
	result, err := h.userService.LoginUser(ctx, service.LoginRequest{
		Email:      req.Email,
		Password:   req.Password,
		DeviceInfo: userAgent,
		IP:         clientIP,
		UserAgent:  userAgent,
	})

	if err != nil {
		switch {
		case errors.Is(err, failure.ErrInvalidCredentials):
			internal.
				Respond(w).
				Status(http.StatusUnauthorized).
				Error(err).Message(failure.ErrInvalidCredentials.Error()).
				Send()
		case errors.Is(err, failure.ErrUserInactive):
			internal.
				Respond(w).
				Status(http.StatusForbidden).
				Error(err).Message(failure.ErrUserInactive.Error()).
				Send()
		case errors.Is(err, failure.ErrTokenGeneration):
			logger.Error().Err(err).Msg("token generation error")
			internal.
				Respond(w).
				Status(http.StatusInternalServerError).
				Error(err).Message(failure.ErrServer.Error()).
				Send()
		default:
			logger.Error().Err(err).Msg("unexpected error during login")
			internal.
				Respond(w).
				Status(http.StatusInternalServerError).
				Error(err).Message(failure.ErrServer.Error()).
				Send()
		}
		return
	}

	response := map[string]any{
		"message":            "login successful",
		"user_id":            result.UserID,
		"email":              result.Email,
		"permissions":        result.Permissions,
		"access_token":       result.AccessToken,
		"refresh_token":      result.RefreshToken,
		"token_type":         "Bearer",
		"expires_in":         result.AccessExpiresIn,
		"refresh_expires_in": result.RefreshExpiresIn,
	}

	internal.Respond(w).OK(response)
}

func (h *UserHandler) NotFound(w http.ResponseWriter, r *http.Request) {
	internal.Respond(w).
		Status(http.StatusNotFound).
		Error(errors.New("endpoint not found")).
		Message("The requested resource does not exist").
		Send()
}

func (h *UserHandler) MethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	internal.Respond(w).
		Status(http.StatusMethodNotAllowed).
		Error(errors.New("method not allowed")).
		Header("Allow", "GET, POST, PUT, DELETE").
		Send()
}

func (h *UserHandler) VerifyToken(w http.ResponseWriter, r *http.Request) {
	var req VerifyTokenRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Warn().
			Err(err).
			Str("path", r.URL.Path).
			Msg("failed to decode verify token request")

		internal.Respond(w).BadRequest(errors.New("invalid request body"))
		return
	}
	defer r.Body.Close()

	if req.Token == "" {
		internal.Respond(w).
			Status(http.StatusBadRequest).
			Message("token is required").
			Send()
		return
	}

	ctx := r.Context()
	result, err := h.userService.VerifyAccessToken(ctx, req.Token)

	if err != nil {
		switch {
		case errors.Is(err, failure.ErrTokenExpired):
			internal.
				Respond(w).
				Status(http.StatusUnauthorized).
				Error(err).Message(failure.ErrTokenExpired.Error()).
				Send()
		case errors.Is(err, failure.ErrInvalidToken):
			internal.
				Respond(w).
				Status(http.StatusUnauthorized).
				Error(err).Message(failure.ErrInvalidToken.Error()).
				Send()
		case errors.Is(err, failure.ErrTokenRevoked):
			internal.
				Respond(w).
				Status(http.StatusUnauthorized).
				Error(err).Message(failure.ErrTokenRevoked.Error()).
				Send()
		case errors.Is(err, failure.ErrUserInactive):
			internal.
				Respond(w).
				Status(http.StatusForbidden).
				Error(err).Message(failure.ErrUserInactive.Error()).
				Send()
		default:
			logger.Error().Err(err).Msg("unexpected error during token verification")
			internal.
				Respond(w).
				Status(http.StatusInternalServerError).
				Error(err).Message(failure.ErrServer.Error()).
				Send()
		}
		return
	}

	response := map[string]any{
		"valid":       result.Valid,
		"user_id":     result.UserID,
		"email":       result.Email,
		"permissions": result.Permissions,
		"expires_at":  result.ExpiresAt,
	}

	internal.Respond(w).OK(response)
}

func (h *UserHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req RefreshTokenRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Warn().
			Err(err).
			Str("path", r.URL.Path).
			Msg("failed to decode refresh token request")

		internal.Respond(w).BadRequest(errors.New("invalid request body"))
		return
	}
	defer r.Body.Close()

	if req.RefreshToken == "" {
		internal.Respond(w).
			Status(http.StatusBadRequest).
			Message("refresh_token is required").
			Send()
		return
	}

	ctx := r.Context()
	result, err := h.userService.RefreshAccessToken(ctx, service.RefreshTokenRequest{
		RefreshToken: req.RefreshToken,
		DeviceInfo:   r.UserAgent(),
	})

	if err != nil {
		switch {
		case errors.Is(err, failure.ErrTokenExpired):
			internal.
				Respond(w).
				Status(http.StatusUnauthorized).
				Error(err).Message(failure.ErrTokenExpired.Error()).
				Send()
		case errors.Is(err, failure.ErrInvalidToken):
			internal.
				Respond(w).
				Status(http.StatusUnauthorized).
				Error(err).Message(failure.ErrInvalidToken.Error()).
				Send()
		case errors.Is(err, failure.ErrUserInactive):
			internal.
				Respond(w).
				Status(http.StatusForbidden).
				Error(err).Message(failure.ErrUserInactive.Error()).
				Send()
		case errors.Is(err, failure.ErrTokenGeneration):
			logger.Error().Err(err).Msg("token generation error")
			internal.
				Respond(w).
				Status(http.StatusInternalServerError).
				Error(err).Message(failure.ErrServer.Error()).
				Send()
		default:
			logger.Error().Err(err).Msg("unexpected error during token refresh")
			internal.
				Respond(w).
				Status(http.StatusInternalServerError).
				Error(err).Message(failure.ErrServer.Error()).
				Send()
		}
		return
	}

	response := map[string]any{
		"access_token":       result.AccessToken,
		"refresh_token":      result.RefreshToken,
		"token_type":         "Bearer",
		"expires_in":         result.AccessExpiresIn,
		"refresh_expires_in": result.RefreshExpiresIn,
	}

	internal.Respond(w).OK(response)
}

func (h *UserHandler) Logout(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		internal.Respond(w).
			Status(http.StatusUnauthorized).
			Message("authorization header required").
			Send()
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		internal.Respond(w).
			Status(http.StatusUnauthorized).
			Message("invalid authorization header format").
			Send()
		return
	}

	accessToken := parts[1]

	ctx := r.Context()
	tokenInfo, err := h.userService.VerifyAccessToken(ctx, accessToken)
	if err != nil {
		if errors.Is(err, failure.ErrTokenExpired) || errors.Is(err, failure.ErrInvalidToken) {
			internal.Respond(w).OK(map[string]any{
				"message": "logged out successfully",
			})
			return
		}

		logger.Error().Err(err).Msg("error verifying token during logout")
		internal.
			Respond(w).
			Status(http.StatusInternalServerError).
			Error(err).Message(failure.ErrServer.Error()).
			Send()
		return
	}

	clientIP := utility.GetClientIP(r)
	userAgent := r.UserAgent()

	err = h.userService.LogoutUser(ctx, accessToken, tokenInfo.UserID, clientIP, userAgent)
	if err != nil {
		logger.Error().
			Err(err).
			Str("user_id", tokenInfo.UserID.String()).
			Msg("failed to logout user")

		internal.
			Respond(w).
			Status(http.StatusInternalServerError).
			Error(err).Message(failure.ErrServer.Error()).
			Send()
		return
	}

	response := map[string]any{
		"message": "logged out successfully",
	}

	internal.Respond(w).OK(response)
}

func (h *UserHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	health := map[string]any{
		"status":  "healthy",
		"version": "1.0.0",
		"service": "goauth",
	}

	internal.Respond(w).OK(health)
}
