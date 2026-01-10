package domain

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidResetToken  = errors.New("invalid or expired reset token")
	ErrResetTokenExpired  = errors.New("reset token has expired")
)

type User struct {
	ID                  uuid.UUID  `json:"id"`
	Email               string     `json:"email"`
	Password            string     `json:"-"`
	Name                string     `json:"name"`
	ResetToken          *string    `json:"-"`
	ResetTokenExpiresAt *time.Time `json:"-"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type AuthResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

type PasswordResetRequest struct {
	Email string `json:"email"`
}

type PasswordResetConfirmRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

type PasswordResetResponse struct {
	Message string `json:"message"`
}
