package loginusecase

import (
	"context"
	"goauth/internal/store"
)

type Params struct {
	Store *store.Store
}

type LoginUseCase struct {
	store *store.Store
}

func New(ctx context.Context, params Params, payload interface{}) *LoginUseCase {
	return &LoginUseCase{}
}

func (u *LoginUseCase) Execute() {}
