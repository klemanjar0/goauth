package grpc

import (
	"context"
	"runtime/debug"
	"strings"
	"time"

	"goauth/internal/logger"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type RequestId string

const requestIdKey RequestId = "request_id"

func requestIDInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		requestID := ""
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if ids := md.Get("x-request-id"); len(ids) > 0 {
				requestID = ids[0]
			}
		}

		if requestID == "" {
			requestID = uuid.New().String()
		}

		ctx = context.WithValue(ctx, requestIdKey, requestID)

		if err := grpc.SetHeader(ctx, metadata.Pairs("x-request-id", requestID)); err != nil {
			logger.Warn().Err(err).Msg("failed to set request ID header")
		}

		return handler(ctx, req)
	}
}

func loggingInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		start := time.Now()

		requestID := ""
		if id, ok := ctx.Value(requestIdKey).(string); ok {
			requestID = id
		}

		resp, err := handler(ctx, req)

		duration := time.Since(start)
		statusCode := codes.OK
		if err != nil {
			if st, ok := status.FromError(err); ok {
				statusCode = st.Code()
			}
		}

		logEvent := logger.Info()
		if requestID != "" {
			logEvent = logEvent.Str("request_id", requestID)
		}

		logEvent.
			Str("method", info.FullMethod).
			Str("code", statusCode.String()).
			Dur("duration", duration).
			Msg("grpc request completed")

		return resp, err
	}
}

func recoveryInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				requestID := ""
				if id, ok := ctx.Value(requestIdKey).(string); ok {
					requestID = id
				}

				stackTrace := string(debug.Stack())

				logEvent := logger.Error().
					Interface("panic", r).
					Str("method", info.FullMethod).
					Str("stack_trace", stackTrace)

				if requestID != "" {
					logEvent = logEvent.Str("request_id", requestID)
				}

				logEvent.Msg("grpc panic recovered")

				// record panic metric
				RecordPanic(info.FullMethod)

				err = status.Errorf(codes.Internal, "internal server error")
			}
		}()

		return handler(ctx, req)
	}
}

func validationInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		if ctx.Err() == context.Canceled {
			return nil, status.Error(codes.Canceled, "request canceled by client")
		}
		if ctx.Err() == context.DeadlineExceeded {
			return nil, status.Error(codes.DeadlineExceeded, "request deadline exceeded")
		}

		if req == nil {
			return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
		}

		return handler(ctx, req)
	}
}

func errorMappingInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		resp, err := handler(ctx, req)
		if err != nil {
			if _, ok := status.FromError(err); ok {
				return resp, err
			}

			err = mapErrorToStatus(err)
		}
		return resp, err
	}
}

func mapErrorToStatus(err error) error {
	if err == nil {
		return nil
	}

	errMsg := err.Error()

	switch {
	case contains(errMsg, "not found"):
		return status.Error(codes.NotFound, err.Error())
	case contains(errMsg, "already exists"):
		return status.Error(codes.AlreadyExists, err.Error())
	case contains(errMsg, "unauthorized"), contains(errMsg, "invalid token"):
		return status.Error(codes.Unauthenticated, err.Error())
	case contains(errMsg, "forbidden"), contains(errMsg, "permission denied"):
		return status.Error(codes.PermissionDenied, err.Error())
	case contains(errMsg, "invalid"), contains(errMsg, "validation failed"):
		return status.Error(codes.InvalidArgument, err.Error())
	case contains(errMsg, "timeout"), contains(errMsg, "deadline exceeded"):
		return status.Error(codes.DeadlineExceeded, err.Error())
	case contains(errMsg, "unavailable"), contains(errMsg, "connection refused"):
		return status.Error(codes.Unavailable, err.Error())
	default:
		return status.Error(codes.Internal, "internal server error")
	}
}

func contains(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
