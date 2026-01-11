package createauditlogusecase

import (
	"context"
	"encoding/json"
	"goauth/internal/store"
	"goauth/internal/store/pg/repository"
	"net/netip"

	"github.com/jackc/pgx/v5/pgtype"
)

type Params struct {
	Store *store.Store
}

type Payload struct {
	UserID                   pgtype.UUID
	EventType, Ip, UserAgent string
	Payload                  map[string]any
}

type CreateAuditLogUseCase struct {
	*Params
	*Payload
	ctx context.Context
}

func New(
	ctx context.Context,
	params *Params,
	payload *Payload,
) *CreateAuditLogUseCase {
	return &CreateAuditLogUseCase{
		Params:  params,
		ctx:     ctx,
		Payload: payload,
	}
}

func (u *CreateAuditLogUseCase) Execute() error {
	userID, eventType, ip, userAgent := u.Payload.UserID, u.Payload.EventType, u.Payload.Ip, u.Payload.UserAgent
	payload := u.Payload.Payload

	params := repository.CreateAuditLogParams{
		EventType: eventType,
	}

	if userID.Valid {
		params.UserID = userID
	}

	if ip != "" {
		addr, err := netip.ParseAddr(ip)
		if err == nil {
			params.Ip = &addr
		}
	}

	if userAgent != "" {
		params.Ua = pgtype.Text{String: userAgent, Valid: true}
	}

	if payload != nil {
		jsonBytes, err := json.Marshal(payload)
		if err == nil {
			params.Payload = jsonBytes
		}
	}

	_, err := u.Store.Queries.CreateAuditLog(u.ctx, params)
	return err
}
