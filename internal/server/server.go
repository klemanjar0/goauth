package server

import (
	"database/sql"
	"goauth/internal/config"
	"goauth/internal/handler"
	"goauth/internal/middleware"
	"goauth/internal/service"
	"goauth/internal/store"
	"goauth/internal/store/pg/repository"
	"net/http"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
)

type Server struct {
	DB             *sql.DB
	Queries        *repository.Queries
	App            *chi.Mux
	ServerInstance *http.Server
	Redis          *store.RedisClient
}

func New(db *sql.DB, q *repository.Queries, c *config.Config, redis *store.RedisClient) *Server {
	r := chi.NewRouter()

	server := &http.Server{
		Addr:    ":" + c.Port,
		Handler: r,
	}

	s := &Server{
		App:            r,
		DB:             db,
		Queries:        q,
		ServerInstance: server,
		Redis:          redis,
	}

	s.setupRoutes()

	return s
}

func (s *Server) setupRoutes() {
	service := service.NewUserService(s.DB, s.Redis.Client)
	handler := handler.NewUserHandler(service)

	s.App.Use(chimiddleware.RequestID)
	s.App.Use(middleware.RequestLogger)
	s.App.Use(middleware.Recoverer)

	s.App.Route("/v1", func(r chi.Router) {
		r.Post("/register", handler.Register)
		r.Post("/login", handler.Login)
		r.Post("/refresh", handler.RefreshToken)
		r.Post("/verify", handler.VerifyToken)
		r.Get("/health", handler.HealthCheck)
	})

	s.App.NotFound(handler.NotFound)
	s.App.MethodNotAllowed(handler.MethodNotAllowed)
}
