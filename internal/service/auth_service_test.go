package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"g-auth/internal/domain"
	"g-auth/pkg/jwt"
	"g-auth/pkg/mailer"
	"g-auth/pkg/password"
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

func (m *MockUserRepository) UpdateMFACode(ctx context.Context, userID uuid.UUID, code string, expiresAt time.Time) error {
	args := m.Called(ctx, userID, code, expiresAt)
	return args.Error(0)
}

func (m *MockUserRepository) ClearMFACode(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserRepository) EnableMFA(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockUserRepository) DisableMFA(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

// MockMailer is a mock implementation of Mailer that can track calls and fail on demand
type MockMailer struct {
	mock.Mock
}

func (m *MockMailer) SendEmail(to, subject, body string) error {
	args := m.Called(to, subject, body)
	return args.Error(0)
}

func (m *MockMailer) SendMFACode(to, name, code string) error {
	args := m.Called(to, name, code)
	return args.Error(0)
}

func setupTestService() (*AuthService, *MockUserRepository) {
	mockRepo := new(MockUserRepository)
	jwtManager := jwt.NewJWTManager("test-secret", time.Hour, 7*24*time.Hour)
	mockMailer := mailer.NewNoOpMailer()
	service := NewAuthService(mockRepo, jwtManager, mockMailer)
	return service, mockRepo
}

func TestNewAuthService(t *testing.T) {
	mockRepo := new(MockUserRepository)
	jwtManager := jwt.NewJWTManager("test-secret", time.Hour, 7*24*time.Hour)
	mockMailer := mailer.NewNoOpMailer()

	service := NewAuthService(mockRepo, jwtManager, mockMailer)

	assert.NotNil(t, service)
	assert.Equal(t, mockRepo, service.userRepo)
	assert.Equal(t, jwtManager, service.jwtManager)
	assert.Equal(t, mockMailer, service.mailer)
}

func TestAuthService_Register_Success(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	req := &domain.RegisterRequest{
		Email:    "test@example.com",
		Password: "password123",
		Name:     "Test User",
	}

	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(nil, domain.ErrUserNotFound)
	mockRepo.On("Create", ctx, mock.AnythingOfType("*domain.User")).Return(nil)
	mockRepo.On("UpdateVerificationToken", ctx, mock.AnythingOfType("uuid.UUID"), mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(nil)

	resp, err := service.Register(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Contains(t, resp.Message, "Registration successful")
	mockRepo.AssertExpectations(t)
}

func TestAuthService_Register_UserAlreadyExists(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	req := &domain.RegisterRequest{
		Email:    "test@example.com",
		Password: "password123",
		Name:     "Test User",
	}

	existingUser := &domain.User{
		ID:    uuid.New(),
		Email: "test@example.com",
	}
	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(existingUser, nil)

	resp, err := service.Register(ctx, req)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrUserAlreadyExists, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_Register_GetByEmailError(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	req := &domain.RegisterRequest{
		Email:    "test@example.com",
		Password: "password123",
		Name:     "Test User",
	}

	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(nil, errors.New("database error"))

	resp, err := service.Register(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_Register_CreateError(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	req := &domain.RegisterRequest{
		Email:    "test@example.com",
		Password: "password123",
		Name:     "Test User",
	}

	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(nil, domain.ErrUserNotFound)
	mockRepo.On("Create", ctx, mock.AnythingOfType("*domain.User")).Return(errors.New("create error"))

	resp, err := service.Register(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_Register_UpdateVerificationTokenError(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	req := &domain.RegisterRequest{
		Email:    "test@example.com",
		Password: "password123",
		Name:     "Test User",
	}

	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(nil, domain.ErrUserNotFound)
	mockRepo.On("Create", ctx, mock.AnythingOfType("*domain.User")).Return(nil)
	mockRepo.On("UpdateVerificationToken", ctx, mock.AnythingOfType("uuid.UUID"), mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(errors.New("update error"))

	resp, err := service.Register(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_Login_Success(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	hashedPassword, _ := password.Hash("password123")
	userID := uuid.New()
	user := &domain.User{
		ID:            userID,
		Email:         "test@example.com",
		Password:      hashedPassword,
		Name:          "Test User",
		EmailVerified: true,
	}

	req := &domain.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(user, nil)
	mockRepo.On("UpdateRefreshToken", ctx, userID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(nil)

	resp, err := service.Login(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Token)
	assert.NotEmpty(t, resp.RefreshToken)
	assert.Equal(t, userID, resp.User.ID)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_Login_UserNotFound(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	req := &domain.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(nil, domain.ErrUserNotFound)

	resp, err := service.Login(ctx, req)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrInvalidCredentials, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_Login_GetByEmailError(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	req := &domain.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(nil, errors.New("database error"))

	resp, err := service.Login(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_Login_ExpiredLock(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	hashedPassword, _ := password.Hash("password123")
	userID := uuid.New()
	expiredLockTime := time.Now().Add(-1 * time.Minute)
	user := &domain.User{
		ID:            userID,
		Email:         "test@example.com",
		Password:      hashedPassword,
		Name:          "Test User",
		EmailVerified: true,
		IsLocked:      true,
		LockedUntil:   &expiredLockTime,
	}

	req := &domain.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(user, nil)
	mockRepo.On("UnlockAccount", ctx, userID).Return(nil)
	mockRepo.On("UpdateRefreshToken", ctx, userID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(nil)

	resp, err := service.Login(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_Login_UnlockAccountError(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	hashedPassword, _ := password.Hash("password123")
	userID := uuid.New()
	expiredLockTime := time.Now().Add(-1 * time.Minute)
	user := &domain.User{
		ID:            userID,
		Email:         "test@example.com",
		Password:      hashedPassword,
		Name:          "Test User",
		EmailVerified: true,
		IsLocked:      true,
		LockedUntil:   &expiredLockTime,
	}

	req := &domain.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(user, nil)
	mockRepo.On("UnlockAccount", ctx, userID).Return(errors.New("unlock error"))

	resp, err := service.Login(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_Login_IncrementFailedAttemptsError(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	hashedPassword, _ := password.Hash("password123")
	userID := uuid.New()
	user := &domain.User{
		ID:            userID,
		Email:         "test@example.com",
		Password:      hashedPassword,
		Name:          "Test User",
		EmailVerified: true,
	}

	req := &domain.LoginRequest{
		Email:    "test@example.com",
		Password: "wrongpassword",
	}

	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(user, nil)
	mockRepo.On("IncrementFailedAttempts", ctx, userID).Return(errors.New("increment error"))

	resp, err := service.Login(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_Login_LockAccountError(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	hashedPassword, _ := password.Hash("password123")
	userID := uuid.New()
	user := &domain.User{
		ID:             userID,
		Email:          "test@example.com",
		Password:       hashedPassword,
		Name:           "Test User",
		EmailVerified:  true,
		FailedAttempts: 4,
	}

	req := &domain.LoginRequest{
		Email:    "test@example.com",
		Password: "wrongpassword",
	}

	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(user, nil)
	mockRepo.On("IncrementFailedAttempts", ctx, userID).Return(nil)
	mockRepo.On("LockAccount", ctx, userID, mock.AnythingOfType("time.Time")).Return(errors.New("lock error"))

	resp, err := service.Login(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_Login_ResetFailedAttemptsError(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	hashedPassword, _ := password.Hash("password123")
	userID := uuid.New()
	user := &domain.User{
		ID:             userID,
		Email:          "test@example.com",
		Password:       hashedPassword,
		Name:           "Test User",
		EmailVerified:  true,
		FailedAttempts: 2,
	}

	req := &domain.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(user, nil)
	mockRepo.On("ResetFailedAttempts", ctx, userID).Return(errors.New("reset error"))

	resp, err := service.Login(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_Login_EmailNotVerified(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	hashedPassword, _ := password.Hash("password123")
	userID := uuid.New()
	user := &domain.User{
		ID:            userID,
		Email:         "test@example.com",
		Password:      hashedPassword,
		Name:          "Test User",
		EmailVerified: false, // Email not verified
	}

	req := &domain.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(user, nil)

	resp, err := service.Login(ctx, req)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrEmailNotVerified, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_Login_UpdateRefreshTokenError(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	hashedPassword, _ := password.Hash("password123")
	userID := uuid.New()
	user := &domain.User{
		ID:            userID,
		Email:         "test@example.com",
		Password:      hashedPassword,
		Name:          "Test User",
		EmailVerified: true,
	}

	req := &domain.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(user, nil)
	mockRepo.On("UpdateRefreshToken", ctx, userID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(errors.New("update error"))

	resp, err := service.Login(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_RefreshToken_Success(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	userID := uuid.New()
	jwtManager := jwt.NewJWTManager("test-secret", time.Hour, 7*24*time.Hour)
	refreshToken, _ := jwtManager.GenerateRefreshToken(userID)
	user := &domain.User{
		ID:    userID,
		Email: "test@example.com",
		Name:  "Test User",
	}

	req := &domain.RefreshTokenRequest{
		RefreshToken: refreshToken,
	}

	mockRepo.On("GetByRefreshToken", ctx, refreshToken).Return(user, nil)
	mockRepo.On("UpdateRefreshToken", ctx, userID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(nil)

	resp, err := service.RefreshToken(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Token)
	assert.NotEmpty(t, resp.RefreshToken)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_RefreshToken_GetByRefreshTokenError(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	userID := uuid.New()
	jwtManager := jwt.NewJWTManager("test-secret", time.Hour, 7*24*time.Hour)
	refreshToken, _ := jwtManager.GenerateRefreshToken(userID)

	req := &domain.RefreshTokenRequest{
		RefreshToken: refreshToken,
	}

	mockRepo.On("GetByRefreshToken", ctx, refreshToken).Return(nil, errors.New("database error"))

	resp, err := service.RefreshToken(ctx, req)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrInvalidCredentials, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_RefreshToken_ExpiredRefreshToken(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	userID := uuid.New()
	jwtManager := jwt.NewJWTManager("test-secret", time.Hour, 7*24*time.Hour)
	refreshToken, _ := jwtManager.GenerateRefreshToken(userID)
	expiredTime := time.Now().Add(-1 * time.Hour)
	user := &domain.User{
		ID:                    userID,
		Email:                 "test@example.com",
		RefreshTokenExpiresAt: &expiredTime,
	}

	req := &domain.RefreshTokenRequest{
		RefreshToken: refreshToken,
	}

	mockRepo.On("GetByRefreshToken", ctx, refreshToken).Return(user, nil)

	resp, err := service.RefreshToken(ctx, req)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrInvalidCredentials, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_RefreshToken_UpdateRefreshTokenError(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	userID := uuid.New()
	jwtManager := jwt.NewJWTManager("test-secret", time.Hour, 7*24*time.Hour)
	refreshToken, _ := jwtManager.GenerateRefreshToken(userID)
	user := &domain.User{
		ID:    userID,
		Email: "test@example.com",
	}

	req := &domain.RefreshTokenRequest{
		RefreshToken: refreshToken,
	}

	mockRepo.On("GetByRefreshToken", ctx, refreshToken).Return(user, nil)
	mockRepo.On("UpdateRefreshToken", ctx, userID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(errors.New("update error"))

	resp, err := service.RefreshToken(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_GetUserByID(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	userID := uuid.New()
	user := &domain.User{
		ID:    userID,
		Email: "test@example.com",
		Name:  "Test User",
	}

	mockRepo.On("GetByID", ctx, userID).Return(user, nil)

	result, err := service.GetUserByID(ctx, userID)

	assert.NoError(t, err)
	assert.Equal(t, user, result)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_GetUserByID_NotFound(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	userID := uuid.New()

	mockRepo.On("GetByID", ctx, userID).Return(nil, domain.ErrUserNotFound)

	result, err := service.GetUserByID(ctx, userID)

	assert.Error(t, err)
	assert.Nil(t, result)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_RequestPasswordReset_UserNotFound(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	req := &domain.PasswordResetRequest{
		Email: "nonexistent@example.com",
	}

	mockRepo.On("GetByEmail", ctx, "nonexistent@example.com").Return(nil, domain.ErrUserNotFound)

	resp, err := service.RequestPasswordReset(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Contains(t, resp.Message, "If the email exists")
	mockRepo.AssertExpectations(t)
}

func TestAuthService_RequestPasswordReset_GetByEmailError(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	req := &domain.PasswordResetRequest{
		Email: "test@example.com",
	}

	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(nil, errors.New("database error"))

	resp, err := service.RequestPasswordReset(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_RequestPasswordReset_UpdateResetTokenError(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	userID := uuid.New()
	user := &domain.User{
		ID:    userID,
		Email: "test@example.com",
		Name:  "Test User",
	}

	req := &domain.PasswordResetRequest{
		Email: "test@example.com",
	}

	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(user, nil)
	mockRepo.On("UpdateResetToken", ctx, userID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(errors.New("update error"))

	resp, err := service.RequestPasswordReset(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_ResetPassword_Success(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	userID := uuid.New()
	validExpiry := time.Now().Add(1 * time.Hour)
	user := &domain.User{
		ID:                  userID,
		Email:               "test@example.com",
		ResetTokenExpiresAt: &validExpiry,
	}

	req := &domain.PasswordResetConfirmRequest{
		Token:    "valid-token",
		Password: "newpassword123",
	}

	mockRepo.On("GetByResetToken", ctx, "valid-token").Return(user, nil)
	mockRepo.On("UpdatePassword", ctx, userID, mock.AnythingOfType("string")).Return(nil)
	mockRepo.On("ClearResetToken", ctx, userID).Return(nil)

	resp, err := service.ResetPassword(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Contains(t, resp.Message, "Password has been reset successfully")
	mockRepo.AssertExpectations(t)
}

func TestAuthService_ResetPassword_TokenNotFound(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	req := &domain.PasswordResetConfirmRequest{
		Token:    "invalid-token",
		Password: "newpassword123",
	}

	mockRepo.On("GetByResetToken", ctx, "invalid-token").Return(nil, domain.ErrUserNotFound)

	resp, err := service.ResetPassword(ctx, req)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrInvalidResetToken, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_ResetPassword_GetByResetTokenError(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	req := &domain.PasswordResetConfirmRequest{
		Token:    "some-token",
		Password: "newpassword123",
	}

	mockRepo.On("GetByResetToken", ctx, "some-token").Return(nil, errors.New("database error"))

	resp, err := service.ResetPassword(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_ResetPassword_NilExpiresAt(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	userID := uuid.New()
	user := &domain.User{
		ID:                  userID,
		Email:               "test@example.com",
		ResetTokenExpiresAt: nil,
	}

	req := &domain.PasswordResetConfirmRequest{
		Token:    "valid-token",
		Password: "newpassword123",
	}

	mockRepo.On("GetByResetToken", ctx, "valid-token").Return(user, nil)

	resp, err := service.ResetPassword(ctx, req)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrResetTokenExpired, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_ResetPassword_UpdatePasswordError(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	userID := uuid.New()
	validExpiry := time.Now().Add(1 * time.Hour)
	user := &domain.User{
		ID:                  userID,
		Email:               "test@example.com",
		ResetTokenExpiresAt: &validExpiry,
	}

	req := &domain.PasswordResetConfirmRequest{
		Token:    "valid-token",
		Password: "newpassword123",
	}

	mockRepo.On("GetByResetToken", ctx, "valid-token").Return(user, nil)
	mockRepo.On("UpdatePassword", ctx, userID, mock.AnythingOfType("string")).Return(errors.New("update error"))

	resp, err := service.ResetPassword(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_ResetPassword_ClearResetTokenError(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	userID := uuid.New()
	validExpiry := time.Now().Add(1 * time.Hour)
	user := &domain.User{
		ID:                  userID,
		Email:               "test@example.com",
		ResetTokenExpiresAt: &validExpiry,
	}

	req := &domain.PasswordResetConfirmRequest{
		Token:    "valid-token",
		Password: "newpassword123",
	}

	mockRepo.On("GetByResetToken", ctx, "valid-token").Return(user, nil)
	mockRepo.On("UpdatePassword", ctx, userID, mock.AnythingOfType("string")).Return(nil)
	mockRepo.On("ClearResetToken", ctx, userID).Return(errors.New("clear error"))

	resp, err := service.ResetPassword(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_VerifyEmail_Success(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	userID := uuid.New()
	validExpiry := time.Now().Add(1 * time.Hour)
	user := &domain.User{
		ID:                         userID,
		Email:                      "test@example.com",
		VerificationTokenExpiresAt: &validExpiry,
	}

	req := &domain.EmailVerificationRequest{
		Token: "valid-token",
	}

	mockRepo.On("GetByVerificationToken", ctx, "valid-token").Return(user, nil)
	mockRepo.On("VerifyEmail", ctx, userID).Return(nil)

	resp, err := service.VerifyEmail(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Contains(t, resp.Message, "Email verified successfully")
	mockRepo.AssertExpectations(t)
}

func TestAuthService_VerifyEmail_TokenNotFound(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	req := &domain.EmailVerificationRequest{
		Token: "invalid-token",
	}

	mockRepo.On("GetByVerificationToken", ctx, "invalid-token").Return(nil, domain.ErrUserNotFound)

	resp, err := service.VerifyEmail(ctx, req)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrInvalidVerificationToken, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_VerifyEmail_GetByVerificationTokenError(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	req := &domain.EmailVerificationRequest{
		Token: "some-token",
	}

	mockRepo.On("GetByVerificationToken", ctx, "some-token").Return(nil, errors.New("database error"))

	resp, err := service.VerifyEmail(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_VerifyEmail_ExpiredToken(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	userID := uuid.New()
	expiredTime := time.Now().Add(-1 * time.Hour)
	user := &domain.User{
		ID:                         userID,
		Email:                      "test@example.com",
		VerificationTokenExpiresAt: &expiredTime,
	}

	req := &domain.EmailVerificationRequest{
		Token: "expired-token",
	}

	mockRepo.On("GetByVerificationToken", ctx, "expired-token").Return(user, nil)

	resp, err := service.VerifyEmail(ctx, req)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrVerificationTokenExpired, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_VerifyEmail_NilExpiresAt(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	userID := uuid.New()
	user := &domain.User{
		ID:                         userID,
		Email:                      "test@example.com",
		VerificationTokenExpiresAt: nil,
	}

	req := &domain.EmailVerificationRequest{
		Token: "valid-token",
	}

	mockRepo.On("GetByVerificationToken", ctx, "valid-token").Return(user, nil)
	mockRepo.On("VerifyEmail", ctx, userID).Return(nil)

	resp, err := service.VerifyEmail(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_VerifyEmail_VerifyEmailError(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	userID := uuid.New()
	user := &domain.User{
		ID:    userID,
		Email: "test@example.com",
	}

	req := &domain.EmailVerificationRequest{
		Token: "valid-token",
	}

	mockRepo.On("GetByVerificationToken", ctx, "valid-token").Return(user, nil)
	mockRepo.On("VerifyEmail", ctx, userID).Return(errors.New("verify error"))

	resp, err := service.VerifyEmail(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_ResendVerification_Success(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	userID := uuid.New()
	user := &domain.User{
		ID:            userID,
		Email:         "test@example.com",
		EmailVerified: false,
	}

	req := &domain.ResendVerificationRequest{
		Email: "test@example.com",
	}

	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(user, nil)
	mockRepo.On("UpdateVerificationToken", ctx, userID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(nil)

	resp, err := service.ResendVerification(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Contains(t, resp.Message, "Verification email sent successfully")
	mockRepo.AssertExpectations(t)
}

func TestAuthService_ResendVerification_UserNotFound(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	req := &domain.ResendVerificationRequest{
		Email: "nonexistent@example.com",
	}

	mockRepo.On("GetByEmail", ctx, "nonexistent@example.com").Return(nil, domain.ErrUserNotFound)

	resp, err := service.ResendVerification(ctx, req)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrUserNotFound, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_ResendVerification_GetByEmailError(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	req := &domain.ResendVerificationRequest{
		Email: "test@example.com",
	}

	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(nil, errors.New("database error"))

	resp, err := service.ResendVerification(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_ResendVerification_AlreadyVerified(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	userID := uuid.New()
	user := &domain.User{
		ID:            userID,
		Email:         "test@example.com",
		EmailVerified: true,
	}

	req := &domain.ResendVerificationRequest{
		Email: "test@example.com",
	}

	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(user, nil)

	resp, err := service.ResendVerification(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Contains(t, resp.Message, "Email is already verified")
	mockRepo.AssertExpectations(t)
}

func TestAuthService_ResendVerification_UpdateVerificationTokenError(t *testing.T) {
	service, mockRepo := setupTestService()
	ctx := context.Background()

	userID := uuid.New()
	user := &domain.User{
		ID:            userID,
		Email:         "test@example.com",
		EmailVerified: false,
	}

	req := &domain.ResendVerificationRequest{
		Email: "test@example.com",
	}

	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(user, nil)
	mockRepo.On("UpdateVerificationToken", ctx, userID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(errors.New("update error"))

	resp, err := service.ResendVerification(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_ResendVerification_SendEmailError(t *testing.T) {
	mockRepo := new(MockUserRepository)
	jwtManager := jwt.NewJWTManager("test-secret", time.Hour, 7*24*time.Hour)
	mockMailer := new(MockMailer)
	service := NewAuthService(mockRepo, jwtManager, mockMailer)

	ctx := context.Background()
	userID := uuid.New()
	user := &domain.User{
		ID:            userID,
		Email:         "test@example.com",
		EmailVerified: false,
	}

	req := &domain.ResendVerificationRequest{
		Email: "test@example.com",
	}

	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(user, nil)
	mockRepo.On("UpdateVerificationToken", ctx, userID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(nil)
	mockMailer.On("SendEmail", "test@example.com", mock.AnythingOfType("string"), mock.AnythingOfType("string")).Return(errors.New("email error"))

	resp, err := service.ResendVerification(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	mockRepo.AssertExpectations(t)
	mockMailer.AssertExpectations(t)
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

func TestAuthService_VerifyMFACode_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	jwtManager := jwt.NewJWTManager("test-secret", time.Hour, 7*24*time.Hour)
	mockMailer := mailer.NewNoOpMailer()
	service := NewAuthService(mockRepo, jwtManager, mockMailer)

	ctx := context.Background()
	userID := uuid.New()
	mfaCode := "123456"
	expiresAt := time.Now().Add(10 * time.Minute)

	user := &domain.User{
		ID:               userID,
		Email:            "test@example.com",
		Name:             "Test User",
		MFAEnabled:       true,
		MFACode:          &mfaCode,
		MFACodeExpiresAt: &expiresAt,
	}

	req := &domain.MFAVerifyRequest{
		Email: "test@example.com",
		Code:  "123456",
	}

	// Mock repository calls
	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(user, nil)
	mockRepo.On("ClearMFACode", ctx, userID).Return(nil)
	mockRepo.On("UpdateRefreshToken", ctx, userID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(nil)

	// Test successful MFA verification
	resp, err := service.VerifyMFACode(ctx, req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Token)
	assert.NotEmpty(t, resp.RefreshToken)
	assert.Equal(t, user.ID, resp.User.ID)
	assert.Equal(t, user.Email, resp.User.Email)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_VerifyMFACode_UserNotFound(t *testing.T) {
	mockRepo := new(MockUserRepository)
	jwtManager := jwt.NewJWTManager("test-secret", time.Hour, 7*24*time.Hour)
	mockMailer := mailer.NewNoOpMailer()
	service := NewAuthService(mockRepo, jwtManager, mockMailer)

	ctx := context.Background()
	req := &domain.MFAVerifyRequest{
		Email: "test@example.com",
		Code:  "123456",
	}

	// Mock GetByEmail to return user not found
	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(nil, domain.ErrUserNotFound)

	// Test MFA verification with non-existent user
	resp, err := service.VerifyMFACode(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, domain.ErrInvalidCredentials, err)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_VerifyMFACode_MFANotEnabled(t *testing.T) {
	mockRepo := new(MockUserRepository)
	jwtManager := jwt.NewJWTManager("test-secret", time.Hour, 7*24*time.Hour)
	mockMailer := mailer.NewNoOpMailer()
	service := NewAuthService(mockRepo, jwtManager, mockMailer)

	ctx := context.Background()
	user := &domain.User{
		ID:         uuid.New(),
		Email:      "test@example.com",
		Name:       "Test User",
		MFAEnabled: false,
	}

	req := &domain.MFAVerifyRequest{
		Email: "test@example.com",
		Code:  "123456",
	}

	// Mock GetByEmail to return user without MFA enabled
	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(user, nil)

	// Test MFA verification when MFA is not enabled
	resp, err := service.VerifyMFACode(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, domain.ErrMFANotEnabled, err)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_VerifyMFACode_NilMFACode(t *testing.T) {
	mockRepo := new(MockUserRepository)
	jwtManager := jwt.NewJWTManager("test-secret", time.Hour, 7*24*time.Hour)
	mockMailer := mailer.NewNoOpMailer()
	service := NewAuthService(mockRepo, jwtManager, mockMailer)

	ctx := context.Background()
	user := &domain.User{
		ID:         uuid.New(),
		Email:      "test@example.com",
		Name:       "Test User",
		MFAEnabled: true,
		MFACode:    nil, // MFA code is nil (already used or cleared)
	}

	req := &domain.MFAVerifyRequest{
		Email: "test@example.com",
		Code:  "123456",
	}

	// Mock GetByEmail to return user with nil MFA code
	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(user, nil)

	// Test MFA verification when MFA code is nil (e.g., already used)
	resp, err := service.VerifyMFACode(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, domain.ErrInvalidMFACode, err)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_VerifyMFACode_InvalidCode(t *testing.T) {
	mockRepo := new(MockUserRepository)
	jwtManager := jwt.NewJWTManager("test-secret", time.Hour, 7*24*time.Hour)
	mockMailer := mailer.NewNoOpMailer()
	service := NewAuthService(mockRepo, jwtManager, mockMailer)

	ctx := context.Background()
	mfaCode := "123456"
	expiresAt := time.Now().Add(10 * time.Minute)

	user := &domain.User{
		ID:               uuid.New(),
		Email:            "test@example.com",
		Name:             "Test User",
		MFAEnabled:       true,
		MFACode:          &mfaCode,
		MFACodeExpiresAt: &expiresAt,
	}

	req := &domain.MFAVerifyRequest{
		Email: "test@example.com",
		Code:  "654321", // wrong code
	}

	// Mock GetByEmail to return user
	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(user, nil)

	// Test MFA verification with invalid code
	resp, err := service.VerifyMFACode(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, domain.ErrInvalidMFACode, err)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_VerifyMFACode_ExpiredCode(t *testing.T) {
	mockRepo := new(MockUserRepository)
	jwtManager := jwt.NewJWTManager("test-secret", time.Hour, 7*24*time.Hour)
	mockMailer := mailer.NewNoOpMailer()
	service := NewAuthService(mockRepo, jwtManager, mockMailer)

	ctx := context.Background()
	mfaCode := "123456"
	expiresAt := time.Now().Add(-10 * time.Minute) // expired

	user := &domain.User{
		ID:               uuid.New(),
		Email:            "test@example.com",
		Name:             "Test User",
		MFAEnabled:       true,
		MFACode:          &mfaCode,
		MFACodeExpiresAt: &expiresAt,
	}

	req := &domain.MFAVerifyRequest{
		Email: "test@example.com",
		Code:  "123456",
	}

	// Mock GetByEmail to return user
	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(user, nil)

	// Test MFA verification with expired code
	resp, err := service.VerifyMFACode(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, domain.ErrMFACodeExpired, err)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_VerifyMFACode_ClearMFACodeError(t *testing.T) {
	mockRepo := new(MockUserRepository)
	jwtManager := jwt.NewJWTManager("test-secret", time.Hour, 7*24*time.Hour)
	mockMailer := mailer.NewNoOpMailer()
	service := NewAuthService(mockRepo, jwtManager, mockMailer)

	ctx := context.Background()
	userID := uuid.New()
	mfaCode := "123456"
	expiresAt := time.Now().Add(10 * time.Minute)

	user := &domain.User{
		ID:               userID,
		Email:            "test@example.com",
		Name:             "Test User",
		MFAEnabled:       true,
		MFACode:          &mfaCode,
		MFACodeExpiresAt: &expiresAt,
	}

	req := &domain.MFAVerifyRequest{
		Email: "test@example.com",
		Code:  "123456",
	}

	// Mock repository calls
	mockRepo.On("GetByEmail", ctx, "test@example.com").Return(user, nil)
	mockRepo.On("ClearMFACode", ctx, userID).Return(errors.New("database error"))

	// Test MFA verification when clearing MFA code fails
	resp, err := service.VerifyMFACode(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "database error")
	mockRepo.AssertExpectations(t)
}
