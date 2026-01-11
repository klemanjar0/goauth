package createauditlogusecase

import (
	"goauth/internal/store"

	"github.com/jackc/pgx/v5/pgtype"
)

type Params struct {
	Store *store.Store
}

type RequestPayload struct {
	UserID                   pgtype.UUID
	EventType, Ip, UserAgent string
	Payload                  map[string]any
}
