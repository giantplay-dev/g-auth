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
	"g-auth/pkg/mailer"
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

func (m *MockUserRepository) UpdateVerificationToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) error {
	args := m.Called(ctx, userID, token, expiresAt)
	return args.Error(0)
}

func (m *MockUserRepository) GetByVerificationToken(ctx context.Context, token string) (*domain.User, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) VerifyEmail(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserRepository) IncrementFailedAttempts(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserRepository) ResetFailedAttempts(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserRepository) LockAccount(ctx context.Context, userID uuid.UUID, lockedUntil time.Time) error {
	args := m.Called(ctx, userID, lockedUntil)
	return args.Error(0)
}

func (m *MockUserRepository) UnlockAccount(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func TestAuthService_RequestPasswordReset(t *testing.T) {
	mockRepo := new(MockUserRepository)
	jwtManager := jwt.NewJWTManager("test-secret", time.Hour, 7*24*time.Hour)
	mockMailer := mailer.NewNoOpMailer()
	service := NewAuthService(mockRepo, jwtManager, mockMailer)

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
	mockMailer := mailer.NewNoOpMailer()
	service := NewAuthService(mockRepo, jwtManager, mockMailer)

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

func TestAuthService_AccountLockout(t *testing.T) {
	mockRepo := new(MockUserRepository)
	jwtManager := jwt.NewJWTManager("test-secret", time.Hour, 7*24*time.Hour)
	mockMailer := mailer.NewNoOpMailer()
	service := NewAuthService(mockRepo, jwtManager, mockMailer)

	ctx := context.Background()
	userID := uuid.New()
	user := &domain.User{
		ID:             userID,
		Email:          "test@example.com",
		Password:       "$2a$10$hashedpassword", // mock hashed password
		Name:           "Test User",
		EmailVerified:  true,
		FailedAttempts: 4, // 4 failed attempts, next one will lock
		IsLocked:       false,
	}

	req := &domain.LoginRequest{
		Email:    "test@example.com",
		Password: "wrongpassword",
	}

	// Mock GetByEmail to return user with 4 failed attempts
	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(user, nil)

	// Mock IncrementFailedAttempts
	mockRepo.On("IncrementFailedAttempts", ctx, userID).Return(nil)

	// Mock LockAccount (should be called after 5th failed attempt)
	mockRepo.On("LockAccount", ctx, userID, mock.AnythingOfType("time.Time")).Return(nil)

	// Test login with wrong password - should lock account
	_, err := service.Login(ctx, req)

	assert.Error(t, err)
	assert.IsType(t, domain.ErrAccountLockedWithTime{}, err)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_LoginLockedAccount(t *testing.T) {
	mockRepo := new(MockUserRepository)
	jwtManager := jwt.NewJWTManager("test-secret", time.Hour, 7*24*time.Hour)
	mockMailer := mailer.NewNoOpMailer()
	service := NewAuthService(mockRepo, jwtManager, mockMailer)

	ctx := context.Background()
	userID := uuid.New()
	lockedUntil := time.Now().Add(15 * time.Minute)
	user := &domain.User{
		ID:          userID,
		Email:       "test@example.com",
		Password:    "$2a$10$hashedpassword",
		Name:        "Test User",
		IsLocked:    true,
		LockedUntil: &lockedUntil,
	}

	req := &domain.LoginRequest{
		Email:    "test@example.com",
		Password: "correctpassword",
	}

	// Mock GetByEmail to return locked user
	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(user, nil)

	// Test login with locked account
	_, err := service.Login(ctx, req)

	assert.Error(t, err)
	expectedErr := domain.ErrAccountLockedWithTime{UnlockTime: lockedUntil}
	assert.Equal(t, expectedErr, err)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_LoginInvalidCredentialsWithAttempts(t *testing.T) {
	mockRepo := new(MockUserRepository)
	jwtManager := jwt.NewJWTManager("test-secret", time.Hour, 7*24*time.Hour)
	mockMailer := mailer.NewNoOpMailer()
	service := NewAuthService(mockRepo, jwtManager, mockMailer)

	ctx := context.Background()
	userID := uuid.New()
	user := &domain.User{
		ID:             userID,
		Email:          "test@example.com",
		Password:       "$2a$10$hashedpassword", // mock hashed password
		Name:           "Test User",
		EmailVerified:  true,
		FailedAttempts: 1, // 1 failed attempt so far
		IsLocked:       false,
	}

	req := &domain.LoginRequest{
		Email:    "test@example.com",
		Password: "wrongpassword",
	}

	// Mock GetByEmail to return user
	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(user, nil)

	// Mock IncrementFailedAttempts
	mockRepo.On("IncrementFailedAttempts", ctx, userID).Return(nil)

	// Test login with wrong password - should return error with remaining attempts
	_, err := service.Login(ctx, req)

	assert.Error(t, err)
	expectedErr := domain.ErrInvalidCredentialsWithAttempts{RemainingAttempts: 3} // 5 - (1 + 1) = 3
	assert.Equal(t, expectedErr, err)
	assert.Contains(t, err.Error(), "3 attempts remaining")
	mockRepo.AssertExpectations(t)
}
