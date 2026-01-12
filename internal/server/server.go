package server

import (
	"goauth/internal/config"
	"goauth/internal/grpc"
	"goauth/internal/handler"
	"goauth/internal/kafka"
	"goauth/internal/logger"
	"goauth/internal/middleware"
	"goauth/internal/service"
	"goauth/internal/store"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Services struct {
	UserService *service.UserService
}

type Server struct {
	Store          *store.Store
	App            *chi.Mux
	ServerInstance *http.Server
	Redis          *store.RedisClient
	KafkaProducer  *kafka.Producer
	GrpcInstance   *grpc.Server
	Config         *config.Config
}

func New(
	pool *pgxpool.Pool,
	c *config.Config,
	redis *store.RedisClient,
	KafkaProducer *kafka.Producer,
) *Server {
	r := chi.NewRouter()
	store := store.NewStore(pool)

	httpServer := &http.Server{
		Addr:    ":" + c.Port,
		Handler: r,
	}

	grpcServer, grpcErr := grpc.NewServer(c, store, redis)

	if grpcErr != nil {
		logger.Fatal().Err(grpcErr).Msg("failed to create grpc server")
	}

	s := &Server{
		App:            r,
		Store:          store,
		ServerInstance: httpServer,
		Redis:          redis,
		KafkaProducer:  KafkaProducer,
		Config:         c,
		GrpcInstance:   grpcServer,
	}

	s.setupRouter()

	return s
}

func (s *Server) setupRouter() {
	userService := service.NewUserService(s.Store, s.Redis.Client, s.KafkaProducer)
	handler := handler.NewUserHandler(userService)

	if len(s.Config.AllowedOrigins) > 0 {
		corsConfig := middleware.CORSConfig{
			AllowedOrigins:   s.Config.AllowedOrigins,
			AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Request-ID"},
			ExposedHeaders:   []string{"X-Request-ID"},
			AllowCredentials: true,
			MaxAge:           300,
		}
		s.App.Use(middleware.CORS(corsConfig))
	}

	s.App.Use(chimiddleware.RequestID)
	s.App.Use(middleware.RequestLogger)
	s.App.Use(middleware.Recoverer)
	s.App.Use(httprate.LimitByIP(100, time.Minute))

	s.App.Route("/v1", func(r chi.Router) {
		r.With(httprate.LimitByIP(5, time.Minute)).Post("/register", handler.Register)
		r.With(httprate.LimitByIP(5, time.Minute)).Post("/login", handler.Login)
		r.With(httprate.LimitByIP(5, time.Minute)).Post("/refresh", handler.RefreshToken)
		r.Post("/me", handler.VerifyToken)
		r.Get("/health", handler.HealthCheck)
		r.Post("/logout", handler.Logout)

		r.With(httprate.LimitByIP(5, time.Minute)).Post("/reset-password", handler.RequestPasswordReset)
		r.Post("/password-update", handler.PasswordReset)
	})

	s.App.Route("/v2", func(r chi.Router) {
		r.With(httprate.LimitByIP(5, time.Minute)).Post("/refresh", handler.RefreshTokenWithCookie)
		r.Post("/logout", handler.LogoutWithCookie)
		r.Post("/me", handler.VerifyCookieToken)
	})

	s.App.Handle("/metrics", promhttp.Handler())

	s.App.Get("/verify-email", handler.VerifyEmail)
	s.App.NotFound(handler.NotFound)
	s.App.MethodNotAllowed(handler.MethodNotAllowed)
}
