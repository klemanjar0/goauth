.PHONY: help build run clean test docker-up docker-down migrate-up migrate-down migrate-force sqlc-generate sqlc-verify proto proto-install

# Default target
help:
	@echo "GoAuth - Makefile Commands"
	@echo ""
	@echo "Development:"
	@echo "  make run              - Run the application"
	@echo "  make build            - Build the application binary"
	@echo "  make clean            - Remove build artifacts"
	@echo "  make test             - Run tests"
	@echo "  make test-coverage    - Run tests with coverage"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-up        - Start all Docker services"
	@echo "  make docker-down      - Stop all Docker services"
	@echo "  make docker-logs      - View Docker logs"
	@echo "  make docker-clean     - Stop and remove all volumes"
	@echo ""
	@echo "Database:"
	@echo "  make migrate-up       - Run all migrations"
	@echo "  make migrate-down     - Rollback last migration"
	@echo "  make migrate-force    - Force migration version (use VERSION=N)"
	@echo "  make migrate-create   - Create new migration (use NAME=migration_name)"
	@echo "  make db-reset         - Reset database (down + up)"
	@echo ""
	@echo "Code Generation:"
	@echo "  make sqlc-generate    - Generate Go code from SQL"
	@echo "  make sqlc-verify      - Verify SQL queries"
	@echo ""
	@echo "Development Tools:"
	@echo "  make fmt              - Format Go code"
	@echo "  make lint             - Run linter"
	@echo "  make deps             - Download dependencies"
	@echo "  make mod-tidy         - Tidy go.mod"

# Variables
DATABASE_URL ?= postgres://postgres:password@localhost:5432/goauth?sslmode=disable
BINARY_NAME = authsvc
BIN_DIR = bin
CMD_DIR = cmd/authsvc
MIGRATIONS_PATH = internal/store/pg/migrations/queries

# Build
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BIN_DIR)
	@go build -o $(BIN_DIR)/$(BINARY_NAME) $(CMD_DIR)/main.go
	@echo "Build complete: $(BIN_DIR)/$(BINARY_NAME)"

# Run
run:
	@echo "Running $(BINARY_NAME)..."
	@go run $(CMD_DIR)/main.go

# Clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BIN_DIR)
	@echo "Clean complete"

# Tests
test:
	@echo "Running tests..."
	@go test -v ./...

test-coverage:
	@echo "Running tests with coverage..."
	@go test -v -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Docker
docker-up:
	@echo "Starting Docker services..."
	@docker-compose up -d
	@echo "Docker services started"

docker-down:
	@echo "Stopping Docker services..."
	@docker-compose down
	@echo "Docker services stopped"

docker-logs:
	@docker-compose logs -f

docker-clean:
	@echo "Stopping and removing all Docker volumes..."
	@docker-compose down -v
	@echo "Docker cleanup complete"

# Database Migrations
migrate-up:
	@echo "Running migrations..."
	@migrate -path $(MIGRATIONS_PATH) -database "$(DATABASE_URL)" up
	@echo "Migrations complete"

migrate-down:
	@echo "Rolling back migration..."
	@migrate -path $(MIGRATIONS_PATH) -database "$(DATABASE_URL)" down 1
	@echo "Rollback complete"

migrate-force:
	@echo "Forcing migration to version $(VERSION)..."
	@migrate -path $(MIGRATIONS_PATH) -database "$(DATABASE_URL)" force $(VERSION)
	@echo "Migration forced to version $(VERSION)"

migrate-create:
	@echo "Creating migration: $(NAME)..."
	@migrate create -ext sql -dir $(MIGRATIONS_PATH) -seq $(NAME)
	@echo "Migration files created"

db-reset:
	@echo "Resetting database..."
	@migrate -path $(MIGRATIONS_PATH) -database "$(DATABASE_URL)" down -all
	@migrate -path $(MIGRATIONS_PATH) -database "$(DATABASE_URL)" up
	@echo "Database reset complete"

# Code Generation
sqlc-generate:
	@echo "Generating Go code from SQL..."
	@sqlc generate
	@echo "Code generation complete"

sqlc-verify:
	@echo "Verifying SQL queries..."
	@sqlc verify
	@echo "SQL verification complete"

proto:
	@echo "Generating proto files to pkg/authpb..."
	@mkdir -p pkg/authpb
	protoc --go_out=. --go_opt=module=goauth \
		--go-grpc_out=. --go-grpc_opt=module=goauth \
		--go_opt=Mapi/proto/auth/v1/auth.proto=goauth/pkg/authpb \
		--go-grpc_opt=Mapi/proto/auth/v1/auth.proto=goauth/pkg/authpb \
		api/proto/auth/v1/auth.proto
	@echo "Proto generation complete"

proto-install:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Development Tools
fmt:
	@echo "Formatting Go code..."
	@go fmt ./...
	@echo "Formatting complete"

lint:
	@echo "Running linter..."
	@golangci-lint run
	@echo "Linting complete"

deps:
	@echo "Downloading dependencies..."
	@go mod download
	@echo "Dependencies downloaded"

mod-tidy:
	@echo "Tidying go.mod..."
	@go mod tidy
	@echo "go.mod tidied"

# Quick start
quickstart: docker-up migrate-up
	@echo ""
	@echo "✅ GoAuth is ready!"
	@echo "Run 'make run' to start the server"
	@echo ""

# Development environment setup
setup: deps docker-up migrate-up sqlc-generate
	@echo ""
	@echo "✅ Development environment setup complete!"
	@echo "Run 'make run' to start the server"
	@echo ""