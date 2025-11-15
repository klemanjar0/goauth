package server

import (
	"goauth/internal/middleware"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
)

type Server struct {
	router *chi.Mux
}

func New() Server {
	r := chi.NewRouter()

	s := Server{
		router: r,
	}

	s.setupRoutes()

	return s
}

func (s Server) setupRoutes() {
	s.router.Use(chimiddleware.RequestID)
	s.router.Use(middleware.RequestLogger)
	s.router.Use(middleware.Recoverer)
}
