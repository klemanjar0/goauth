package middleware

import (
	"goauth/internal/logger"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		requestID := middleware.GetReqID(r.Context())

		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		defer func() {
			logger.Info().
				Str("request_id", requestID).
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Str("remote_addr", r.RemoteAddr).
				Int("status", ww.Status()).
				Int("bytes", ww.BytesWritten()).
				Dur("duration_ms", time.Since(start)).
				Msg("request completed")
		}()

		next.ServeHTTP(ww, r)
	})
}
