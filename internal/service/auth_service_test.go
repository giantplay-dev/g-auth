package service

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"g-auth/internal/domain"
	"g-auth/pkg/jwt"
)

// MockUserRepository is a mock implementation of UserRepository
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) UpdateResetToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) error {
	args := m.Called(ctx, userID, token, expiresAt)
	return args.Error(0)
}

func (m *MockUserRepository) GetByResetToken(ctx context.Context, token string) (*domain.User, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) UpdatePassword(ctx context.Context, userID uuid.UUID, hashedPassword string) error {
	args := m.Called(ctx, userID, hashedPassword)
	return args.Error(0)
}

func (m *MockUserRepository) ClearResetToken(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserRepository) UpdateRefreshToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) error {
	args := m.Called(ctx, userID, token, expiresAt)
	return args.Error(0)
}

func (m *MockUserRepository) GetByRefreshToken(ctx context.Context, token string) (*domain.User, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) ClearRefreshToken(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func TestAuthService_RequestPasswordReset(t *testing.T) {
	mockRepo := new(MockUserRepository)
	jwtManager := jwt.NewJWTManager("test-secret", time.Hour, 7*24*time.Hour)
	service := NewAuthService(mockRepo, jwtManager)

	ctx := context.Background()
	req := &domain.PasswordResetRequest{Email: "test@example.com"}

	user := &domain.User{
		ID:    uuid.New(),
		Email: "test@example.com",
		Name:  "Test User",
	}

	// Test successful password reset request
	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(user, nil)
	mockRepo.On("UpdateResetToken", ctx, mock.AnythingOfType("uuid.UUID"), mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(nil)

	resp, err := service.RequestPasswordReset(ctx, req)

	assert.NoError(t, err)
	assert.Equal(t, "If the email exists, a password reset link has been sent", resp.Message)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_RefreshToken(t *testing.T) {
	mockRepo := new(MockUserRepository)
	jwtManager := jwt.NewJWTManager("test-secret", time.Hour, 7*24*time.Hour)
	service := NewAuthService(mockRepo, jwtManager)

	ctx := context.Background()
	user := &domain.User{
		ID:    uuid.New(),
		Email: "test@example.com",
		Name:  "Test User",
	}

	// Generate a valid refresh token
	refreshToken, err := jwtManager.GenerateRefreshToken(user.ID)
	assert.NoError(t, err)

	req := &domain.RefreshTokenRequest{RefreshToken: refreshToken}

	// Mock the repository calls
	mockRepo.On("GetByRefreshToken", ctx, refreshToken).Return(user, nil)
	mockRepo.On("UpdateRefreshToken", ctx, user.ID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(nil)

	// Test successful token refresh
	resp, err := service.RefreshToken(ctx, req)

	assert.NoError(t, err)
	assert.NotEmpty(t, resp.Token)
	assert.NotEmpty(t, resp.RefreshToken)
	assert.Equal(t, user.ID, resp.User.ID)
	assert.Equal(t, user.Email, resp.User.Email)
	mockRepo.AssertExpectations(t)
}
