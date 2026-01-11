package registerusecase

import (
	"goauth/internal/store"
	createauditlogusecase "goauth/internal/usecase/create_audit_log_use_case"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/redis/go-redis/v9"
)

type Params struct {
	Store                 *store.Store
	RedisClient           *redis.Client
	CreateAuditLogUseCase *createauditlogusecase.CreateAuditLogUseCase
}

type RequestPayload struct {
	Email       string
	Password    string
	Permissions int64
	IP          string
	UserAgent   string
}

type Response struct {
	UserID         pgtype.UUID
	Email          string
	Permissions    int64
	IsActive       bool
	EmailConfirmed bool
	CreatedAt      time.Time
}
