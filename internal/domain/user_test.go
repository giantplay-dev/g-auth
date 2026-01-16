package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestErrAccountLockedWithTime_Error(t *testing.T) {
	unlockTime := time.Date(2026, 1, 16, 15, 30, 45, 0, time.UTC)
	err := ErrAccountLockedWithTime{UnlockTime: unlockTime}

	result := err.Error()

	assert.Contains(t, result, "Account temporarily locked")
	assert.Contains(t, result, "15:30:45")
}

func TestErrInvalidCredentialsWithAttempts_Error_SingleAttempt(t *testing.T) {
	err := ErrInvalidCredentialsWithAttempts{RemainingAttempts: 1}

	result := err.Error()

	assert.Contains(t, result, "Invalid email or password")
	assert.Contains(t, result, "1 attempt remaining")
}

func TestErrInvalidCredentialsWithAttempts_Error_MultipleAttempts(t *testing.T) {
	err := ErrInvalidCredentialsWithAttempts{RemainingAttempts: 3}

	result := err.Error()

	assert.Contains(t, result, "Invalid email or password")
	assert.Contains(t, result, "3 attempts remaining")
}

func TestErrInvalidCredentialsWithAttempts_Error_ZeroAttempts(t *testing.T) {
	err := ErrInvalidCredentialsWithAttempts{RemainingAttempts: 0}

	result := err.Error()

	assert.Contains(t, result, "Invalid email or password")
	assert.Contains(t, result, "0 attempts remaining")
}

func TestErrorMessages(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"ErrUserNotFound", ErrUserNotFound, "user not found"},
		{"ErrUserAlreadyExists", ErrUserAlreadyExists, "user already exists"},
		{"ErrInvalidCredentials", ErrInvalidCredentials, "Invalid email or password"},
		{"ErrInvalidResetToken", ErrInvalidResetToken, "invalid or expired reset token"},
		{"ErrInvalidVerificationToken", ErrInvalidVerificationToken, "invalid or expired verification token"},
		{"ErrResetTokenExpired", ErrResetTokenExpired, "reset token has expired"},
		{"ErrVerificationTokenExpired", ErrVerificationTokenExpired, "verification token has expired"},
		{"ErrEmailNotVerified", ErrEmailNotVerified, "Please verify your email address before logging in"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestUser_Structure(t *testing.T) {
	user := User{
		Email:         "test@example.com",
		Name:          "Test User",
		EmailVerified: false,
	}

	assert.Equal(t, "test@example.com", user.Email)
	assert.Equal(t, "Test User", user.Name)
	assert.False(t, user.EmailVerified)
}

func TestLoginRequest_Structure(t *testing.T) {
	req := LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	assert.Equal(t, "test@example.com", req.Email)
	assert.Equal(t, "password123", req.Password)
}

func TestRegisterRequest_Structure(t *testing.T) {
	req := RegisterRequest{
		Email:    "test@example.com",
		Password: "password123",
		Name:     "Test User",
	}

	assert.Equal(t, "test@example.com", req.Email)
	assert.Equal(t, "password123", req.Password)
	assert.Equal(t, "Test User", req.Name)
}

func TestRefreshTokenRequest_Structure(t *testing.T) {
	req := RefreshTokenRequest{
		RefreshToken: "some-refresh-token",
	}

	assert.Equal(t, "some-refresh-token", req.RefreshToken)
}

func TestRegisterResponse_Structure(t *testing.T) {
	resp := RegisterResponse{
		Message: "Success",
	}

	assert.Equal(t, "Success", resp.Message)
}

func TestAuthResponse_Structure(t *testing.T) {
	user := User{Email: "test@example.com"}
	resp := AuthResponse{
		Token:        "access-token",
		RefreshToken: "refresh-token",
		User:         user,
	}

	assert.Equal(t, "access-token", resp.Token)
	assert.Equal(t, "refresh-token", resp.RefreshToken)
	assert.Equal(t, user, resp.User)
}

func TestPasswordResetRequest_Structure(t *testing.T) {
	req := PasswordResetRequest{
		Email: "test@example.com",
	}

	assert.Equal(t, "test@example.com", req.Email)
}

func TestPasswordResetConfirmRequest_Structure(t *testing.T) {
	req := PasswordResetConfirmRequest{
		Token:    "reset-token",
		Password: "new-password",
	}

	assert.Equal(t, "reset-token", req.Token)
	assert.Equal(t, "new-password", req.Password)
}

func TestPasswordResetResponse_Structure(t *testing.T) {
	resp := PasswordResetResponse{
		Message: "Password reset successful",
	}

	assert.Equal(t, "Password reset successful", resp.Message)
}

func TestEmailVerificationRequest_Structure(t *testing.T) {
	req := EmailVerificationRequest{
		Token: "verification-token",
	}

	assert.Equal(t, "verification-token", req.Token)
}

func TestEmailVerificationResponse_Structure(t *testing.T) {
	resp := EmailVerificationResponse{
		Message: "Email verified",
	}

	assert.Equal(t, "Email verified", resp.Message)
}

func TestResendVerificationRequest_Structure(t *testing.T) {
	req := ResendVerificationRequest{
		Email: "test@example.com",
	}

	assert.Equal(t, "test@example.com", req.Email)
}

func TestResendVerificationResponse_Structure(t *testing.T) {
	resp := ResendVerificationResponse{
		Message: "Verification email sent",
	}

	assert.Equal(t, "Verification email sent", resp.Message)
}
