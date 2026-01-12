package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"goauth/internal"
	"goauth/internal/failure"
	"goauth/internal/logger"
	"goauth/internal/service"
	loginusecase "goauth/internal/usecase/login_use_case"
	refreshaccesstokenusecase "goauth/internal/usecase/refresh_access_token_use_case"
	registerusecase "goauth/internal/usecase/register_use_case"
	resetpasswordusecase "goauth/internal/usecase/reset_password_use_case"
	verifyaccesstokenusecase "goauth/internal/usecase/verify_access_token_use_case"
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

type ResetPasswordEmailRequest struct {
	Email string `json:"email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func NewUserHandler(userService *service.UserService) *UserHandler {
	return &UserHandler{
		userService: userService,
	}
}

const REQUEST_CTX_TIMEOUT = time.Second * 5

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

	ctx, cancel := context.WithTimeout(r.Context(), REQUEST_CTX_TIMEOUT)
	defer cancel()

	result, err := u.userService.RegisterUser(ctx, registerusecase.Payload{
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

	u.userService.SendVerificationEmail(ctx, result)

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

	ctx, cancel := context.WithTimeout(r.Context(), REQUEST_CTX_TIMEOUT)
	defer cancel()

	result, err := h.userService.LoginUser(ctx, loginusecase.Payload{
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

	h.SetAuthCookies(w, result.AccessToken, result.RefreshToken, result.AccessExpiresIn, result.RefreshExpiresIn)

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

func (h *UserHandler) VerifyCookieToken(w http.ResponseWriter, r *http.Request) {
	token, err := utility.GetAuthToken(r, utility.AccessTokenKey)

	if err != nil {
		switch {
		case errors.Is(err, failure.ErrTokenIsEmpty):
			internal.
				Respond(w).
				Status(http.StatusUnauthorized).
				Error(err).Message(failure.ErrTokenIsEmpty.Error()).
				Send()
		case errors.Is(err, http.ErrNoCookie):
			internal.
				Respond(w).
				Status(http.StatusUnauthorized).
				Error(err).Message(http.ErrNoCookie.Error()).
				Send()

			return
		}

		internal.Respond(w).BadRequest(err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), REQUEST_CTX_TIMEOUT)
	defer cancel()

	result, verifyErr := h.userService.VerifyAccessToken(ctx, verifyaccesstokenusecase.Payload{Token: token})

	if verifyErr != nil {
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

	ctx, cancel := context.WithTimeout(r.Context(), REQUEST_CTX_TIMEOUT)
	defer cancel()

	result, err := h.userService.VerifyAccessToken(ctx, verifyaccesstokenusecase.Payload{Token: req.Token})

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

	ctx, cancel := context.WithTimeout(r.Context(), REQUEST_CTX_TIMEOUT)
	defer cancel()
	result, err := h.userService.RefreshAccessToken(ctx, refreshaccesstokenusecase.Payload{
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
		case errors.Is(err, failure.ErrTokenRevoked):
			internal.
				Respond(w).
				Status(http.StatusUnauthorized).
				Error(err).Message(failure.ErrTokenRevoked.Error()).
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

func (h *UserHandler) SetAuthCookies(w http.ResponseWriter, access, refresh string, accessExpiresIn, refreshExpiresIn int64) {
	http.SetCookie(w, &http.Cookie{
		Name:     utility.AccessTokenKey,
		Value:    access,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   int(accessExpiresIn),
	})

	http.SetCookie(w, &http.Cookie{
		Name:     utility.RefreshTokenKey,
		Value:    refresh,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/v2/refresh",
		MaxAge:   int(refreshExpiresIn),
	})
}

func (h *UserHandler) RefreshTokenWithCookie(w http.ResponseWriter, r *http.Request) {
	token, err := utility.GetAuthToken(r, utility.RefreshTokenKey)

	if token == "" || err != nil {
		internal.Respond(w).
			Error(err).
			Status(http.StatusBadRequest).
			Message("refresh_toke cookie is required").
			Send()
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), REQUEST_CTX_TIMEOUT)
	defer cancel()

	result, err := h.userService.RefreshAccessToken(ctx, refreshaccesstokenusecase.Payload{
		RefreshToken: token,
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
		case errors.Is(err, failure.ErrTokenRevoked):
			internal.
				Respond(w).
				Status(http.StatusUnauthorized).
				Error(err).Message(failure.ErrTokenRevoked.Error()).
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

	h.SetAuthCookies(w, result.AccessToken, result.RefreshToken, result.AccessExpiresIn, result.RefreshExpiresIn)

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

	ctx, cancel := context.WithTimeout(r.Context(), REQUEST_CTX_TIMEOUT)
	defer cancel()

	tokenInfo, err := h.userService.VerifyAccessToken(ctx, verifyaccesstokenusecase.Payload{Token: accessToken})
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

func (h *UserHandler) LogoutWithCookie(w http.ResponseWriter, r *http.Request) {
	token, err := utility.GetAuthToken(r, utility.AccessTokenKey)

	if token == "" {
		internal.Respond(w).
			Status(http.StatusUnauthorized).
			Message("access token cookie is required").
			Send()
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), REQUEST_CTX_TIMEOUT)
	defer cancel()

	tokenInfo, err := h.userService.VerifyAccessToken(ctx, verifyaccesstokenusecase.Payload{Token: token})
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

	err = h.userService.LogoutUser(ctx, token, tokenInfo.UserID, clientIP, userAgent)
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

	http.SetCookie(w, &http.Cookie{
		Name:     utility.AccessTokenKey,
		Value:    "",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   -1,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     utility.RefreshTokenKey,
		Value:    "",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
		MaxAge:   -1,
	})

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

func (h *UserHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")

	if token == "" {
		internal.
			Respond(w).
			Status(http.StatusBadRequest).
			Message(failure.ErrInvalidToken.Error()).
			Send()
		return
	}

	if err := h.userService.VerifyEmail(r.Context(), token); err != nil {
		logger.Error().
			Err(err).
			Str("token", token).
			Msg("failed to verify")

		internal.Respond(w).Status(http.StatusBadRequest).Text("Failed to verify email. Try again later.").SendText()
		return
	}

	internal.Respond(w).Status(http.StatusAccepted).Text("Email has been successfully verified").SendText()
}

func (h *UserHandler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req ResetPasswordEmailRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Warn().
			Err(err).
			Str("path", r.URL.Path).
			Msg("failed to decode password reset email request")

		internal.Respond(w).BadRequest(errors.New("invalid request body"))
		return
	}
	defer r.Body.Close()

	if req.Email == "" {
		internal.
			Respond(w).
			Status(http.StatusBadRequest).
			Message(failure.ErrInvalidEmail.Error()).
			Send()
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), REQUEST_CTX_TIMEOUT)
	defer cancel()

	if err := h.userService.SendPasswordResetEmail(ctx, req.Email); err != nil {
		switch {
		case errors.Is(err, failure.ErrDatabaseError):
			logger.Error().Err(err).Str("email", req.Email).Msg("database error during password reset request")
			internal.
				Respond(w).
				Status(http.StatusInternalServerError).
				Error(err).Message(failure.ErrServer.Error()).
				Send()
		default:
			logger.Error().Err(err).Str("email", req.Email).Msg("unexpected error during password reset request")
			internal.
				Respond(w).
				Status(http.StatusInternalServerError).
				Error(err).Message(failure.ErrServer.Error()).
				Send()
		}
		return
	}

	response := map[string]any{
		"message": "reset password mail has been successfully send",
	}

	internal.Respond(w).OK(response)
}

func (h *UserHandler) PasswordReset(w http.ResponseWriter, r *http.Request) {
	var req ResetPasswordRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.Warn().
			Err(err).
			Str("path", r.URL.Path).
			Msg("failed to decode password reset request")

		internal.Respond(w).BadRequest(errors.New("invalid request body"))
		return
	}
	defer r.Body.Close()

	if req.Token == "" {
		internal.
			Respond(w).
			Status(http.StatusBadRequest).
			Message("token is required").
			Send()
		return
	}

	if req.NewPassword == "" {
		internal.
			Respond(w).
			Status(http.StatusBadRequest).
			Message("new_password is required").
			Send()
		return
	}

	clientIP := utility.GetClientIP(r)
	userAgent := r.UserAgent()
	ctx, cancel := context.WithTimeout(r.Context(), REQUEST_CTX_TIMEOUT)
	defer cancel()

	if err := h.userService.ResetPassword(ctx, resetpasswordusecase.Payload{
		Token:       req.Token,
		NewPassword: req.NewPassword,
		IP:          clientIP,
		UserAgent:   userAgent,
	}); err != nil {
		switch {
		case errors.Is(err, failure.ErrTokenInvalid):
			logger.Warn().Err(err).Msg("invalid or expired password reset token")
			internal.
				Respond(w).
				Status(http.StatusBadRequest).
				Error(err).Message(failure.ErrTokenInvalid.Error()).
				Send()
		case errors.Is(err, failure.ErrPasswordTooWeak):
			logger.Warn().Err(err).Msg("weak password during password reset")
			internal.
				Respond(w).
				Status(http.StatusBadRequest).
				Error(err).Message(failure.ErrPasswordTooWeak.Error()).
				Send()
		case errors.Is(err, failure.ErrPasswordHashError):
			logger.Error().Err(err).Msg("password hashing error during password reset")
			internal.
				Respond(w).
				Status(http.StatusInternalServerError).
				Error(err).Message(failure.ErrServer.Error()).
				Send()
		case errors.Is(err, failure.ErrDatabaseError):
			logger.Error().Err(err).Msg("database error during password reset")
			internal.
				Respond(w).
				Status(http.StatusInternalServerError).
				Error(err).Message(failure.ErrServer.Error()).
				Send()
		case errors.Is(err, failure.ErrPasswordReset):
			logger.Error().Err(err).Msg("password reset transaction failed")
			internal.
				Respond(w).
				Status(http.StatusInternalServerError).
				Error(err).Message(failure.ErrServer.Error()).
				Send()
		default:
			logger.Error().Err(err).Msg("unexpected error during password reset")
			internal.
				Respond(w).
				Status(http.StatusInternalServerError).
				Error(err).Message(failure.ErrServer.Error()).
				Send()
		}
		return
	}

	response := map[string]any{
		"message": "password has been successfully changed",
	}

	internal.Respond(w).OK(response)
}
