package repository

import (
	"context"
	"time"

	"g-auth/internal/domain"

	"github.com/google/uuid"
)

type UserRepository interface {
	Create(ctx context.Context, user *domain.User) error
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
	UpdateResetToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) error
	GetByResetToken(ctx context.Context, token string) (*domain.User, error)
	UpdatePassword(ctx context.Context, userID uuid.UUID, hashedPassword string) error
	ClearResetToken(ctx context.Context, userID uuid.UUID) error
}
