package utility

import (
	"goauth/internal/failure"
	"net/http"
	"regexp"
	"strings"
	"unicode"

	"github.com/google/uuid"
)

const (
	minPasswordLength = 8
)

var (
	EmailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
)

func ValidatePassword(password string) error {
	if len(password) < minPasswordLength {
		return failure.ErrPasswordTooShort
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasNumber || !hasSpecial {
		return failure.ErrPasswordTooWeak
	}

	return nil
}

func ValidateEmail(email string) error {
	if email == "" {
		return failure.ErrInvalidEmail
	}

	email = strings.TrimSpace(email)

	if len(email) > 254 {
		return failure.ErrInvalidEmail
	}

	if !EmailRegex.MatchString(email) {
		return failure.ErrInvalidEmail
	}

	return nil
}

func GetClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}

func GetRequestID(r *http.Request) string {
	// Try to get from context or header
	if reqID := r.Header.Get("X-Request-ID"); reqID != "" {
		return reqID
	}
	return "unknown"
}

func ParseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}
