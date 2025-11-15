package middleware

import (
	"goauth/internal/logger"
	"net/http"
	"runtime/debug"
)

func Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				logger.Error().
					Interface("panic", err).
					Str("stack", string(debug.Stack())).
					Str("path", r.URL.Path).
					Msg("panic recovered")

				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("internal server error"))
			}
		}()

		next.ServeHTTP(w, r)
	})
}
