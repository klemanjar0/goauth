package server

import (
	"database/sql"
	"goauth/internal/config"
	"goauth/internal/grpc"
	"goauth/internal/handler"
	"goauth/internal/logger"
	"goauth/internal/middleware"
	"goauth/internal/service"
	"goauth/internal/store"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type KafkaServices struct {
	EmailService *service.EmailService
}

type Services struct {
	UserService *service.UserService
}

type Server struct {
	Store          *store.Store
	App            *chi.Mux
	ServerInstance *http.Server
	Redis          *store.RedisClient
	KafkaServices  *KafkaServices
	GrpcInstance   *grpc.Server
	Services       *Services
	Config         *config.Config
}

func New(
	db *sql.DB,
	c *config.Config,
	redis *store.RedisClient,
	kServices *KafkaServices,
) *Server {
	r := chi.NewRouter()
	store := store.NewStore(db)

	httpServer := &http.Server{
		Addr:    ":" + c.Port,
		Handler: r,
	}

	services := initServices(store, redis, kServices)

	s := &Server{
		App:            r,
		Store:          store,
		ServerInstance: httpServer,
		Redis:          redis,
		KafkaServices:  kServices,
		Config:         c,
		Services:       services,
		GrpcInstance:   initGrpc(c, services, redis),
	}

	s.initRoutes()

	return s
}

func initServices(
	store *store.Store,
	redis *store.RedisClient,
	kServices *KafkaServices,
) *Services {
	userService := service.NewUserService(store, redis.Client, kServices.EmailService)

	return &Services{
		UserService: userService,
	}
}

func initGrpc(
	config *config.Config,
	services *Services,
	redis *store.RedisClient,
) *grpc.Server {
	grpcServer, err := grpc.NewServer(config, services.UserService, redis)

	if err != nil {
		logger.Fatal().Err(err).Msg("failed to create grpc server")
	}

	return grpcServer
}

func (s *Server) initRoutes() {
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

	// Prometheus metrics endpoint
	s.App.Handle("/metrics", promhttp.Handler())

	s.App.Get("/verify-email", handler.VerifyEmail)
	s.App.NotFound(handler.NotFound)
	s.App.MethodNotAllowed(handler.MethodNotAllowed)
}
