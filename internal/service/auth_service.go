package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"

	"g-auth/internal/domain"
	"g-auth/internal/repository"
	"g-auth/pkg/jwt"
	"g-auth/pkg/mailer"
	"g-auth/pkg/password"
)

type AuthService struct {
	userRepo   repository.UserRepository
	jwtManager *jwt.JWTManager
	mailer     mailer.Mailer
}

func NewAuthService(userRepo repository.UserRepository, jwtManager *jwt.JWTManager, mailer mailer.Mailer) *AuthService {
	return &AuthService{
		userRepo:   userRepo,
		jwtManager: jwtManager,
		mailer:     mailer,
	}
}

func (s *AuthService) Register(ctx context.Context, req *domain.RegisterRequest) (*domain.RegisterResponse, error) {
	// check if user already exists
	existingUser, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil && !errors.Is(err, domain.ErrUserNotFound) {
		return nil, err
	}
	if existingUser != nil {
		return nil, domain.ErrUserAlreadyExists
	}

	// hash password
	hashedPassword, err := password.Hash(req.Password)
	if err != nil {
		return nil, err
	}

	// create user
	user := &domain.User{
		Email:         req.Email,
		Password:      hashedPassword,
		Name:          req.Name,
		EmailVerified: false,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	// generate verification token
	verificationToken, err := s.generateToken()
	if err != nil {
		return nil, err
	}

	// set verification token with expiration (24 hours)
	expiresAt := time.Now().Add(24 * time.Hour)
	err = s.userRepo.UpdateVerificationToken(ctx, user.ID, verificationToken, expiresAt)
	if err != nil {
		return nil, err
	}

	// send verification email
	err = s.sendVerificationEmail(user.Email, verificationToken)
	if err != nil {
		// log error but don't fail registration
		// in production, you might want to handle this differently
	}

	return &domain.RegisterResponse{
		Message: "Registration successful. Please check your email to verify your account.",
	}, nil

}

func (s *AuthService) Login(ctx context.Context, req *domain.LoginRequest) (*domain.AuthResponse, error) {
	// get user by email
	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, domain.ErrInvalidCredentials
		}
		return nil, err
	}

	// check if account is locked
	if user.IsLocked {
		if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
			return nil, domain.ErrAccountLockedWithTime{UnlockTime: *user.LockedUntil}
		} else {
			// unlock account if lock period has expired
			err = s.userRepo.UnlockAccount(ctx, user.ID)
			if err != nil {
				return nil, err
			}
			user.IsLocked = false
			user.FailedAttempts = 0
		}
	}

	// verify password
	if !password.Verify(req.Password, user.Password) {
		// increment failed attempts
		err = s.userRepo.IncrementFailedAttempts(ctx, user.ID)
		if err != nil {
			return nil, err
		}

		// calculate remaining attempts (5 total allowed - current failed attempts)
		remainingAttempts := 5 - (user.FailedAttempts + 1)

		// check if account should be locked (after 5 failed attempts)
		if user.FailedAttempts >= 4 { // 4 because it will be incremented to 5
			lockedUntil := time.Now().Add(15 * time.Minute) // lock for 15 minutes
			err = s.userRepo.LockAccount(ctx, user.ID, lockedUntil)
			if err != nil {
				return nil, err
			}
			return nil, domain.ErrAccountLockedWithTime{UnlockTime: lockedUntil}
		}

		return nil, domain.ErrInvalidCredentialsWithAttempts{RemainingAttempts: remainingAttempts}
	}

	// reset failed attempts on successful login
	if user.FailedAttempts > 0 {
		err = s.userRepo.ResetFailedAttempts(ctx, user.ID)
		if err != nil {
			return nil, err
		}
	}

	// check if email is verified
	if !user.EmailVerified {
		return nil, domain.ErrEmailNotVerified
	}

	// generate tokens
	token, err := s.jwtManager.Generate(user.ID, user.Email)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.jwtManager.GenerateRefreshToken(user.ID)
	if err != nil {
		return nil, err
	}

	// store refresh token
	refreshExpiresAt := time.Now().Add(7 * 24 * time.Hour) // 7 days
	err = s.userRepo.UpdateRefreshToken(ctx, user.ID, refreshToken, refreshExpiresAt)
	if err != nil {
		return nil, err
	}

	return &domain.AuthResponse{
		Token:        token,
		RefreshToken: refreshToken,
		User:         *user,
	}, nil
}

func (s *AuthService) RefreshToken(ctx context.Context, req *domain.RefreshTokenRequest) (*domain.AuthResponse, error) {
	// verify refresh token
	_, err := s.jwtManager.VerifyRefreshToken(req.RefreshToken)
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	// get user by refresh token from database
	user, err := s.userRepo.GetByRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	// check if refresh token is expired
	if user.RefreshTokenExpiresAt != nil && user.RefreshTokenExpiresAt.Before(time.Now()) {
		return nil, domain.ErrInvalidCredentials
	}

	// generate new tokens
	token, err := s.jwtManager.Generate(user.ID, user.Email)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.jwtManager.GenerateRefreshToken(user.ID)
	if err != nil {
		return nil, err
	}

	// update refresh token in database
	refreshExpiresAt := time.Now().Add(7 * 24 * time.Hour) // 7 days
	err = s.userRepo.UpdateRefreshToken(ctx, user.ID, refreshToken, refreshExpiresAt)
	if err != nil {
		return nil, err
	}

	return &domain.AuthResponse{
		Token:        token,
		RefreshToken: refreshToken,
		User:         *user,
	}, nil
}

func (s *AuthService) GetUserByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	return s.userRepo.GetByID(ctx, id)
}

func (s *AuthService) RequestPasswordReset(ctx context.Context, req *domain.PasswordResetRequest) (*domain.PasswordResetResponse, error) {
	// get user by email
	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			// Don't reveal if email exists or not for security
			return &domain.PasswordResetResponse{
				Message: "If the email exists, a password reset link has been sent",
			}, nil
		}
		return nil, err
	}

	// generate reset token
	token, err := s.generateResetToken()
	if err != nil {
		return nil, err
	}

	// set expiration time (24 hours from now)
	expiresAt := time.Now().Add(24 * time.Hour)

	// update user with reset token
	err = s.userRepo.UpdateResetToken(ctx, user.ID, token, expiresAt)
	if err != nil {
		return nil, err
	}

	// send email with reset link
	resetLink := "http://localhost:8080/reset-password?token=" + token // TODO: Make this configurable
	emailBody := s.buildPasswordResetEmail(user.Name, resetLink)
	err = s.mailer.SendEmail(user.Email, "Password Reset Request", emailBody)
	if err != nil {
		// Log the error but don't fail the request for security reasons
		// In production, you might want to retry or alert administrators
		// For now, we'll just log it (assuming logger is available)
		// TODO: Add proper logging
	}

	return &domain.PasswordResetResponse{
		Message: "If the email exists, a password reset link has been sent",
	}, nil
}

func (s *AuthService) ResetPassword(ctx context.Context, req *domain.PasswordResetConfirmRequest) (*domain.PasswordResetResponse, error) {
	// get user by reset token
	user, err := s.userRepo.GetByResetToken(ctx, req.Token)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, domain.ErrInvalidResetToken
		}
		return nil, err
	}

	// check if token is expired
	if user.ResetTokenExpiresAt == nil || user.ResetTokenExpiresAt.Before(time.Now()) {
		return nil, domain.ErrResetTokenExpired
	}

	// hash new password
	hashedPassword, err := password.Hash(req.Password)
	if err != nil {
		return nil, err
	}

	// update password and clear reset token
	err = s.userRepo.UpdatePassword(ctx, user.ID, hashedPassword)
	if err != nil {
		return nil, err
	}

	err = s.userRepo.ClearResetToken(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	return &domain.PasswordResetResponse{
		Message: "Password has been reset successfully",
	}, nil
}

func (s *AuthService) generateResetToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (s *AuthService) buildPasswordResetEmail(name, resetLink string) string {
	return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Password Reset</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #4CAF50;">Password Reset Request</h2>
        
        <p>Hello ` + name + `,</p>
        
        <p>You have requested to reset your password. Please click the link below to reset your password:</p>
        
        <p style="text-align: center; margin: 30px 0;">
            <a href="` + resetLink + `" 
               style="background-color: #4CAF50; color: white; padding: 12px 24px; 
                      text-decoration: none; border-radius: 4px; display: inline-block;">
                Reset Password
            </a>
        </p>
        
        <p><strong>Important:</strong> This link will expire in 24 hours for security reasons.</p>
        
        <p>If you didn't request this password reset, please ignore this email. Your password will remain unchanged.</p>
        
        <p>If the button above doesn't work, you can copy and paste this link into your browser:</p>
        <p style="word-break: break-all; color: #666;">` + resetLink + `</p>
        
        <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
        
        <p style="color: #666; font-size: 12px;">
            This is an automated email. Please do not reply to this message.
        </p>
    </div>
</body>
</html>
`
}

func (s *AuthService) VerifyEmail(ctx context.Context, req *domain.EmailVerificationRequest) (*domain.EmailVerificationResponse, error) {
	// get user by verification token
	user, err := s.userRepo.GetByVerificationToken(ctx, req.Token)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, domain.ErrInvalidVerificationToken
		}
		return nil, err
	}

	// check if token is expired
	if user.VerificationTokenExpiresAt != nil && time.Now().After(*user.VerificationTokenExpiresAt) {
		return nil, domain.ErrVerificationTokenExpired
	}

	// verify email
	err = s.userRepo.VerifyEmail(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	return &domain.EmailVerificationResponse{
		Message: "Email verified successfully. You can now log in.",
	}, nil
}

func (s *AuthService) ResendVerification(ctx context.Context, req *domain.ResendVerificationRequest) (*domain.ResendVerificationResponse, error) {
	// get user by email
	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}

	// check if already verified
	if user.EmailVerified {
		return &domain.ResendVerificationResponse{
			Message: "Email is already verified.",
		}, nil
	}

	// generate new verification token
	verificationToken, err := s.generateToken()
	if err != nil {
		return nil, err
	}

	// set verification token with expiration (24 hours)
	expiresAt := time.Now().Add(24 * time.Hour)
	err = s.userRepo.UpdateVerificationToken(ctx, user.ID, verificationToken, expiresAt)
	if err != nil {
		return nil, err
	}

	// send verification email
	err = s.sendVerificationEmail(user.Email, verificationToken)
	if err != nil {
		return nil, err
	}

	return &domain.ResendVerificationResponse{
		Message: "Verification email sent successfully.",
	}, nil
}

func (s *AuthService) generateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (s *AuthService) sendVerificationEmail(email, token string) error {
	verificationLink := "http://localhost:8080/api/v1/auth/verify-email?token=" + token // adjust URL as needed

	subject := "Verify Your Email Address"
	htmlBody := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Verify Your Email</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: #f8f9fa; padding: 30px; border-radius: 10px;">
        <h2 style="color: #007bff; margin-bottom: 20px;">Verify Your Email Address</h2>
        
        <p>Hello,</p>
        
        <p>Thank you for registering with our service. To complete your registration, please verify your email address by clicking the button below:</p>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="` + verificationLink + `" style="background-color: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Verify Email</a>
        </div>
        
        <p><strong>Important:</strong> This link will expire in 24 hours for security reasons.</p>
        
        <p>If the button above doesn't work, you can copy and paste this link into your browser:</p>
        <p style="word-break: break-all; color: #666;">` + verificationLink + `</p>
        
        <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
        
        <p style="color: #666; font-size: 12px;">
            This is an automated email. Please do not reply to this message.
        </p>
    </div>
</body>
</html>
`

	return s.mailer.SendEmail(email, subject, htmlBody)
}
