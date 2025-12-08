package grpc

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	grpcRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "grpc_server_request_duration_seconds",
			Help:    "Duration of gRPC requests in seconds",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"method", "code"},
	)

	grpcRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "grpc_server_requests_total",
			Help: "Total number of gRPC requests",
		},
		[]string{"method", "code"},
	)

	grpcActiveRequests = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "grpc_server_active_requests",
			Help: "Number of active gRPC requests",
		},
		[]string{"method"},
	)

	grpcRequestSize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "grpc_server_request_size_bytes",
			Help:    "Size of gRPC requests in bytes",
			Buckets: []float64{64, 256, 1024, 4096, 16384, 65536, 262144, 1048576},
		},
		[]string{"method"},
	)

	grpcResponseSize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "grpc_server_response_size_bytes",
			Help:    "Size of gRPC responses in bytes",
			Buckets: []float64{64, 256, 1024, 4096, 16384, 65536, 262144, 1048576},
		},
		[]string{"method"},
	)

	grpcErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "grpc_server_errors_total",
			Help: "Total number of gRPC errors",
		},
		[]string{"method", "code"},
	)

	grpcPanicsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "grpc_server_panics_total",
			Help: "Total number of gRPC panics recovered",
		},
		[]string{"method"},
	)
)

func metricsInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		start := time.Now()
		method := info.FullMethod

		grpcActiveRequests.WithLabelValues(method).Inc()
		defer grpcActiveRequests.WithLabelValues(method).Dec()

		resp, err := handler(ctx, req)

		duration := time.Since(start).Seconds()

		code := codes.OK
		if err != nil {
			if st, ok := status.FromError(err); ok {
				code = st.Code()
			} else {
				code = codes.Unknown
			}
		}

		codeStr := code.String()

		grpcRequestsTotal.WithLabelValues(method, codeStr).Inc()
		grpcRequestDuration.WithLabelValues(method, codeStr).Observe(duration)

		if code != codes.OK {
			grpcErrorsTotal.WithLabelValues(method, codeStr).Inc()
		}

		return resp, err
	}
}

func RecordPanic(method string) {
	grpcPanicsTotal.WithLabelValues(method).Inc()
}
