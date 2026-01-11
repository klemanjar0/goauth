package grpc

import (
	"fmt"
	"goauth/internal/config"
	"goauth/internal/grpc/handler"
	"goauth/internal/store"
	"goauth/pkg/authpb"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"

	"goauth/internal/logger"
)

type Server struct {
	server      *grpc.Server
	listener    net.Listener
	authHandler *handler.AuthHandler
}

func NewServer(cfg *config.Config, store *store.Store, redisClient *store.RedisClient) (*Server, error) {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", cfg.GRPCConfig.Port))
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %w", err)
	}

	rateLimiter := NewGRPCRateLimiter(redisClient.Client, RateLimiterConfig{
		RequestsPerWindow: 100,
		WindowDuration:    time.Minute,
		KeyPrefix:         "grpc:ratelimit",
	})

	serverOpts := []grpc.ServerOption{
		// order matters!
		grpc.ChainUnaryInterceptor(
			recoveryInterceptor(),
			requestIDInterceptor(),
			metricsInterceptor(),
			rateLimiter.Interceptor(),
			validationInterceptor(),
			loggingInterceptor(),
			errorMappingInterceptor(),
		),

		grpc.ConnectionTimeout(120 * time.Second),
		grpc.MaxConcurrentStreams(1000),
		grpc.MaxRecvMsgSize(4 * 1024 * 1024), // 4MB
		grpc.MaxSendMsgSize(4 * 1024 * 1024), // 4MB

		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle:     15 * time.Minute,
			MaxConnectionAge:      30 * time.Minute,
			MaxConnectionAgeGrace: 5 * time.Minute,
			Time:                  5 * time.Minute,
			Timeout:               1 * time.Minute,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             1 * time.Minute,
			PermitWithoutStream: true,
		}),
	}

	if cfg.GRPCConfig.TLSEnabled {
		if cfg.GRPCConfig.CertFile == "" || cfg.GRPCConfig.KeyFile == "" {
			return nil, fmt.Errorf("TLS enabled but cert or key file not provided")
		}

		creds, err := credentials.NewServerTLSFromFile(
			cfg.GRPCConfig.CertFile,
			cfg.GRPCConfig.KeyFile,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS credentials: %w", err)
		}

		serverOpts = append(serverOpts, grpc.Creds(creds))
		logger.Info().Msg("gRPC server TLS enabled")
	} else {
		logger.Warn().Msg("gRPC server running without TLS")
	}

	grpcServer := grpc.NewServer(serverOpts...)

	authHandler := handler.NewAuthHandler(store, redisClient.Client)
	authpb.RegisterAuthServiceServer(grpcServer, authHandler)

	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

	reflection.Register(grpcServer)

	return &Server{
		server:      grpcServer,
		listener:    lis,
		authHandler: authHandler,
	}, nil
}

func (s *Server) Start() error {
	logger.Info().
		Str("addr", s.listener.Addr().String()).
		Msg("starting grpc server")
	return s.server.Serve(s.listener)
}

func (s *Server) Stop() {
	logger.Info().Msg("stopping grpc server")
	s.server.GracefulStop()
}
