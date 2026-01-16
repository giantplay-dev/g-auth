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
	UpdateRefreshToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) error
	GetByRefreshToken(ctx context.Context, token string) (*domain.User, error)
	ClearRefreshToken(ctx context.Context, userID uuid.UUID) error
	UpdateVerificationToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) error
	GetByVerificationToken(ctx context.Context, token string) (*domain.User, error)
	VerifyEmail(ctx context.Context, userID uuid.UUID) error
	IncrementFailedAttempts(ctx context.Context, userID uuid.UUID) error
	ResetFailedAttempts(ctx context.Context, userID uuid.UUID) error
	LockAccount(ctx context.Context, userID uuid.UUID, lockedUntil time.Time) error
	UnlockAccount(ctx context.Context, userID uuid.UUID) error
	UpdateMFACode(ctx context.Context, userID uuid.UUID, code string, expiresAt time.Time) error
	ClearMFACode(ctx context.Context, userID uuid.UUID) error
	EnableMFA(ctx context.Context, userID uuid.UUID) error
	DisableMFA(ctx context.Context, userID uuid.UUID) error
}
