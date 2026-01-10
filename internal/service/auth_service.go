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
	"g-auth/pkg/password"
)

type AuthService struct {
	userRepo   repository.UserRepository
	jwtManager *jwt.JWTManager
}

func NewAuthService(userRepo repository.UserRepository, jwtManager *jwt.JWTManager) *AuthService {
	return &AuthService{
		userRepo:   userRepo,
		jwtManager: jwtManager,
	}
}

func (s *AuthService) Register(ctx context.Context, req *domain.RegisterRequest) (*domain.AuthResponse, error) {
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
		Email:    req.Email,
		Password: hashedPassword,
		Name:     req.Name,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, err
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

func (s *AuthService) Login(ctx context.Context, req *domain.LoginRequest) (*domain.AuthResponse, error) {
	// get user by email
	user, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, domain.ErrInvalidCredentials
		}
		return nil, err
	}

	// verify password
	if !password.Verify(req.Password, user.Password) {
		return nil, domain.ErrInvalidCredentials
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

	// TODO: Send email with reset link
	// For now, just return success message
	// In production, you would send an email with a link like:
	// https://yourapp.com/reset-password?token={token}

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
