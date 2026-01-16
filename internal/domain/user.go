package domain

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var (
	ErrUserNotFound             = errors.New("user not found")
	ErrUserAlreadyExists        = errors.New("user already exists")
	ErrInvalidCredentials       = errors.New("Invalid email or password")
	ErrInvalidResetToken        = errors.New("invalid or expired reset token")
	ErrInvalidVerificationToken = errors.New("invalid or expired verification token")
	ErrResetTokenExpired        = errors.New("reset token has expired")
	ErrVerificationTokenExpired = errors.New("verification token has expired")
	ErrEmailNotVerified         = errors.New("Please verify your email address before logging in")
)

// ErrAccountLockedWithTime represents an account locked error with unlock time information
type ErrAccountLockedWithTime struct {
	UnlockTime time.Time
}

func (e ErrAccountLockedWithTime) Error() string {
	return fmt.Sprintf("Account temporarily locked due to too many failed login attempts. You can try again after %s.", e.UnlockTime.Format("15:04:05"))
}

// ErrInvalidCredentialsWithAttempts represents an invalid credentials error with attempt information
type ErrInvalidCredentialsWithAttempts struct {
	RemainingAttempts int
}

func (e ErrInvalidCredentialsWithAttempts) Error() string {
	if e.RemainingAttempts == 1 {
		return "Invalid email or password. 1 attempt remaining before account lockout."
	}
	return fmt.Sprintf("Invalid email or password. %d attempts remaining before account lockout.", e.RemainingAttempts)
}

type User struct {
	ID                         uuid.UUID  `json:"id"`
	Email                      string     `json:"email"`
	Password                   string     `json:"-"`
	Name                       string     `json:"name"`
	EmailVerified              bool       `json:"email_verified"`
	VerificationToken          *string    `json:"-"`
	VerificationTokenExpiresAt *time.Time `json:"-"`
	ResetToken                 *string    `json:"-"`
	ResetTokenExpiresAt        *time.Time `json:"-"`
	RefreshToken               *string    `json:"-"`
	RefreshTokenExpiresAt      *time.Time `json:"-"`
	FailedAttempts             int        `json:"-"`
	LockedUntil                *time.Time `json:"-"`
	IsLocked                   bool       `json:"-"`
	CreatedAt                  time.Time  `json:"created_at"`
	UpdatedAt                  time.Time  `json:"updated_at"`
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

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type RegisterResponse struct {
	Message string `json:"message"`
}

type AuthResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	User         User   `json:"user"`
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

type EmailVerificationRequest struct {
	Token string `json:"token"`
}

type EmailVerificationResponse struct {
	Message string `json:"message"`
}

type ResendVerificationRequest struct {
	Email string `json:"email"`
}

type ResendVerificationResponse struct {
	Message string `json:"message"`
}
