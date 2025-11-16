package server

import (
	"database/sql"
	"goauth/internal/middleware"
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
}

func New(db *sql.DB, q *repository.Queries, port string) *Server {
	r := chi.NewRouter()

	server := &http.Server{
		Addr:    ":" + port,
		Handler: r,
	}

	s := &Server{
		App:            r,
		DB:             db,
		Queries:        q,
		ServerInstance: server,
	}

	s.setupRoutes()

	return s
}

func (s Server) setupRoutes() {
	s.App.Use(chimiddleware.RequestID)
	s.App.Use(middleware.RequestLogger)
	s.App.Use(middleware.Recoverer)
}
