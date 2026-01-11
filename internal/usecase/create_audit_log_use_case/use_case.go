package createauditlogusecase

import (
	"context"
	"encoding/json"
	"goauth/internal/store"
	"goauth/internal/store/pg/repository"
	"net/netip"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/redis/go-redis/v9"
)

type CreateAuditLogUseCase struct {
	store       *store.Store
	redisClient *redis.Client

	payload *RequestPayload
	ctx     context.Context
}

func New(
	ctx context.Context,
	params Params,
) *CreateAuditLogUseCase {
	return &CreateAuditLogUseCase{
		store: params.Store,
		ctx:   ctx,
	}
}

func (u *CreateAuditLogUseCase) WithPayload(payload *RequestPayload) *CreateAuditLogUseCase {
	u.payload = payload
	return u
}

func (u *CreateAuditLogUseCase) Execute() error {
	userID, eventType, ip, userAgent := u.payload.UserID, u.payload.EventType, u.payload.Ip, u.payload.UserAgent
	payload := u.payload.Payload

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

	_, err := u.store.Queries.CreateAuditLog(u.ctx, params)
	return err
}
