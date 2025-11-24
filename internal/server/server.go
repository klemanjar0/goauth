package server

import (
	"database/sql"
	"goauth/internal/config"
	"goauth/internal/handler"
	"goauth/internal/middleware"
	"goauth/internal/service"
	"goauth/internal/store"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
)

type KafkaServices struct {
	EmailService *service.EmailService
}

type Server struct {
	Store          *store.Store
	App            *chi.Mux
	ServerInstance *http.Server
	Redis          *store.RedisClient
	KafkaServices  *KafkaServices
}

func New(db *sql.DB, c *config.Config, redis *store.RedisClient, kServices *KafkaServices) *Server {
	r := chi.NewRouter()

	server := &http.Server{
		Addr:    ":" + c.Port,
		Handler: r,
	}

	s := &Server{
		App:            r,
		Store:          store.NewStore(db),
		ServerInstance: server,
		Redis:          redis,
		KafkaServices:  kServices,
	}

	s.setupRoutes()

	return s
}

func (s *Server) setupRoutes() {
	service := service.NewUserService(s.Store, s.Redis.Client, s.KafkaServices.EmailService)
	handler := handler.NewUserHandler(service)

	globalRateLimiter := middleware.NewRateLimiter(s.Redis.Client, middleware.RateLimiterConfig{
		RequestsPerWindow: 100,
		WindowDuration:    time.Minute,
		KeyPrefix:         "ratelimit:global",
	})

	authRateLimiter := middleware.NewRateLimiter(s.Redis.Client, middleware.RateLimiterConfig{
		RequestsPerWindow: 5,
		WindowDuration:    time.Minute,
		KeyPrefix:         "ratelimit:auth",
	})

	s.App.Use(chimiddleware.RequestID)
	s.App.Use(middleware.RequestLogger)
	s.App.Use(middleware.Recoverer)
	s.App.Use(globalRateLimiter.Middleware)

	s.App.Route("/v1", func(r chi.Router) {
		r.Post("/register", handler.Register)
		r.Post("/login", handler.Login)
		r.Post("/refresh", handler.RefreshToken)
		r.Post("/verify", handler.VerifyToken)
		r.Get("/health", handler.HealthCheck)

		r.With(authRateLimiter.Middleware).Post("/reset-password", handler.RequestPasswordReset)
		r.Post("/password-update", handler.PasswordReset)
	})

	s.App.Get("/verify-email", handler.VerifyEmail)
	s.App.NotFound(handler.NotFound)
	s.App.MethodNotAllowed(handler.MethodNotAllowed)
}
