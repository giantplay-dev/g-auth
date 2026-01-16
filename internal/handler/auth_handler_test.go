package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"g-auth/internal/domain"
	"g-auth/internal/middleware"
	"g-auth/internal/service"
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

func setupTestHandler() (*AuthHandler, *MockUserRepository) {
	mockRepo := new(MockUserRepository)
	jwtManager := jwt.NewJWTManager("test-secret", time.Hour, 7*24*time.Hour)
	mockMailer := mailer.NewNoOpMailer()
	authService := service.NewAuthService(mockRepo, jwtManager, mockMailer)
	handler := NewAuthHandler(authService)
	return handler, mockRepo
}

func TestNewAuthHandler(t *testing.T) {
	handler, _ := setupTestHandler()
	assert.NotNil(t, handler)
}

func TestAuthHandler_SetupRoutes(t *testing.T) {
	handler, _ := setupTestHandler()
	router := handler.SetupRoutes()
	assert.NotNil(t, router)
}

func TestAuthHandler_Health(t *testing.T) {
	handler, _ := setupTestHandler()

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	handler.Health(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "ok", response["status"])
}

func TestAuthHandler_Register_Success(t *testing.T) {
	handler, mockRepo := setupTestHandler()

	reqBody := domain.RegisterRequest{
		Email:    "test@example.com",
		Password: "password123",
		Name:     "Test User",
	}
	body, _ := json.Marshal(reqBody)

	mockRepo.On("GetByEmail", mock.Anything, "test@example.com").Return(nil, domain.ErrUserNotFound)
	mockRepo.On("Create", mock.Anything, mock.AnythingOfType("*domain.User")).Return(nil)
	mockRepo.On("UpdateVerificationToken", mock.Anything, mock.AnythingOfType("uuid.UUID"), mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(nil)

	req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.Register(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestAuthHandler_Register_InvalidPayload(t *testing.T) {
	handler, _ := setupTestHandler()

	req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.Register(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_Register_UserAlreadyExists(t *testing.T) {
	handler, mockRepo := setupTestHandler()

	reqBody := domain.RegisterRequest{
		Email:    "test@example.com",
		Password: "password123",
		Name:     "Test User",
	}
	body, _ := json.Marshal(reqBody)

	existingUser := &domain.User{
		ID:    uuid.New(),
		Email: "test@example.com",
	}
	mockRepo.On("GetByEmail", mock.Anything, "test@example.com").Return(existingUser, nil)

	req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.Register(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestAuthHandler_Register_InternalError(t *testing.T) {
	handler, mockRepo := setupTestHandler()

	reqBody := domain.RegisterRequest{
		Email:    "test@example.com",
		Password: "password123",
		Name:     "Test User",
	}
	body, _ := json.Marshal(reqBody)

	mockRepo.On("GetByEmail", mock.Anything, "test@example.com").Return(nil, errors.New("database error"))

	req := httptest.NewRequest("POST", "/api/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.Register(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAuthHandler_Login_InvalidPayload(t *testing.T) {
	handler, _ := setupTestHandler()

	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.Login(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_Login_InvalidCredentials(t *testing.T) {
	handler, mockRepo := setupTestHandler()

	reqBody := domain.LoginRequest{
		Email:    "test@example.com",
		Password: "wrongpassword",
	}
	body, _ := json.Marshal(reqBody)

	mockRepo.On("GetByEmail", mock.Anything, "test@example.com").Return(nil, domain.ErrUserNotFound)

	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.Login(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_Login_InvalidCredentialsWithAttempts(t *testing.T) {
	handler, mockRepo := setupTestHandler()

	reqBody := domain.LoginRequest{
		Email:    "test@example.com",
		Password: "wrongpassword",
	}
	body, _ := json.Marshal(reqBody)

	user := &domain.User{
		ID:             uuid.New(),
		Email:          "test@example.com",
		Password:       "$2a$10$invalidhash", // Will fail password verification
		EmailVerified:  true,
		FailedAttempts: 2,
	}
	mockRepo.On("GetByEmail", mock.Anything, "test@example.com").Return(user, nil)
	mockRepo.On("IncrementFailedAttempts", mock.Anything, user.ID).Return(nil)

	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.Login(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_Login_Success(t *testing.T) {
	handler, mockRepo := setupTestHandler()

	userID := uuid.New()
	hashedPassword, _ := password.Hash("password123")
	user := &domain.User{
		ID:            userID,
		Email:         "test@example.com",
		Password:      hashedPassword,
		Name:          "Test User",
		EmailVerified: true,
	}

	reqBody := domain.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}
	body, _ := json.Marshal(reqBody)

	mockRepo.On("GetByEmail", mock.Anything, "test@example.com").Return(user, nil)
	mockRepo.On("ResetFailedAttempts", mock.Anything, userID).Return(nil)
	mockRepo.On("UpdateRefreshToken", mock.Anything, userID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(nil)

	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.Login(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response domain.AuthResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.NotEmpty(t, response.Token)
	assert.NotEmpty(t, response.RefreshToken)
}

func TestAuthHandler_Login_AccountLocked(t *testing.T) {
	handler, mockRepo := setupTestHandler()

	reqBody := domain.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}
	body, _ := json.Marshal(reqBody)

	lockedUntil := time.Now().Add(15 * time.Minute)
	user := &domain.User{
		ID:          uuid.New(),
		Email:       "test@example.com",
		Password:    "$2a$10$invalidhash",
		IsLocked:    true,
		LockedUntil: &lockedUntil,
	}
	mockRepo.On("GetByEmail", mock.Anything, "test@example.com").Return(user, nil)

	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.Login(w, req)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

func TestAuthHandler_Login_InternalError(t *testing.T) {
	handler, mockRepo := setupTestHandler()

	reqBody := domain.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}
	body, _ := json.Marshal(reqBody)

	mockRepo.On("GetByEmail", mock.Anything, "test@example.com").Return(nil, errors.New("database error"))

	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.Login(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAuthHandler_Login_EmailNotVerified(t *testing.T) {
	handler, mockRepo := setupTestHandler()

	userID := uuid.New()
	hashedPassword, _ := password.Hash("password123")
	user := &domain.User{
		ID:            userID,
		Email:         "test@example.com",
		Password:      hashedPassword,
		Name:          "Test User",
		EmailVerified: false,
	}

	reqBody := domain.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}
	body, _ := json.Marshal(reqBody)

	mockRepo.On("GetByEmail", mock.Anything, "test@example.com").Return(user, nil)

	req := httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.Login(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "verify your email")
}

func TestAuthHandler_RefreshToken_InvalidPayload(t *testing.T) {
	handler, _ := setupTestHandler()

	req := httptest.NewRequest("POST", "/api/auth/refresh", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.RefreshToken(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_RefreshToken_InvalidCredentials(t *testing.T) {
	handler, _ := setupTestHandler()

	reqBody := domain.RefreshTokenRequest{
		RefreshToken: "invalid-token",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/auth/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.RefreshToken(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_RefreshToken_InternalError(t *testing.T) {
	handler, mockRepo := setupTestHandler()

	// First create a valid refresh token
	userID := uuid.New()
	user := &domain.User{
		ID:            userID,
		Email:         "test@example.com",
		Name:          "Test User",
		EmailVerified: true,
	}

	// Generate a valid refresh token to use
	jwtManager := jwt.NewJWTManager("test-secret", time.Hour, 7*24*time.Hour)
	refreshToken, _ := jwtManager.GenerateRefreshToken(userID)

	reqBody := domain.RefreshTokenRequest{
		RefreshToken: refreshToken,
	}
	body, _ := json.Marshal(reqBody)

	// Return user for the first call but then simulate an internal error
	mockRepo.On("GetByRefreshToken", mock.Anything, refreshToken).Return(user, nil)
	mockRepo.On("UpdateRefreshToken", mock.Anything, userID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(errors.New("database error"))

	req := httptest.NewRequest("POST", "/api/auth/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.RefreshToken(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAuthHandler_RefreshToken_Success(t *testing.T) {
	handler, mockRepo := setupTestHandler()

	userID := uuid.New()
	user := &domain.User{
		ID:            userID,
		Email:         "test@example.com",
		Name:          "Test User",
		EmailVerified: true,
	}

	// Generate a valid refresh token to use
	jwtManager := jwt.NewJWTManager("test-secret", time.Hour, 7*24*time.Hour)
	refreshToken, _ := jwtManager.GenerateRefreshToken(userID)

	reqBody := domain.RefreshTokenRequest{
		RefreshToken: refreshToken,
	}
	body, _ := json.Marshal(reqBody)

	mockRepo.On("GetByRefreshToken", mock.Anything, refreshToken).Return(user, nil)
	mockRepo.On("UpdateRefreshToken", mock.Anything, userID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(nil)

	req := httptest.NewRequest("POST", "/api/auth/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.RefreshToken(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response domain.AuthResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.NotEmpty(t, response.Token)
	assert.NotEmpty(t, response.RefreshToken)
}

func TestAuthHandler_GetMe_Success(t *testing.T) {
	handler, mockRepo := setupTestHandler()

	userID := uuid.New()
	user := &domain.User{
		ID:    userID,
		Email: "test@example.com",
		Name:  "Test User",
	}
	mockRepo.On("GetByID", mock.Anything, userID).Return(user, nil)

	req := httptest.NewRequest("GET", "/api/me", nil)
	ctx := context.WithValue(req.Context(), middleware.UserIDKey, userID)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.GetMe(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthHandler_GetMe_NotFound(t *testing.T) {
	handler, mockRepo := setupTestHandler()

	userID := uuid.New()
	mockRepo.On("GetByID", mock.Anything, userID).Return(nil, domain.ErrUserNotFound)

	req := httptest.NewRequest("GET", "/api/me", nil)
	ctx := context.WithValue(req.Context(), middleware.UserIDKey, userID)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.GetMe(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAuthHandler_RequestPasswordReset_InvalidPayload(t *testing.T) {
	handler, _ := setupTestHandler()

	req := httptest.NewRequest("POST", "/api/auth/password-reset", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.RequestPasswordReset(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_RequestPasswordReset_Success(t *testing.T) {
	handler, mockRepo := setupTestHandler()

	reqBody := domain.PasswordResetRequest{
		Email: "test@example.com",
	}
	body, _ := json.Marshal(reqBody)

	user := &domain.User{
		ID:    uuid.New(),
		Email: "test@example.com",
		Name:  "Test User",
	}
	mockRepo.On("GetByEmail", mock.Anything, "test@example.com").Return(user, nil)
	mockRepo.On("UpdateResetToken", mock.Anything, user.ID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(nil)

	req := httptest.NewRequest("POST", "/api/auth/password-reset", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.RequestPasswordReset(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthHandler_RequestPasswordReset_UserNotFound(t *testing.T) {
	handler, mockRepo := setupTestHandler()

	reqBody := domain.PasswordResetRequest{
		Email: "nonexistent@example.com",
	}
	body, _ := json.Marshal(reqBody)

	mockRepo.On("GetByEmail", mock.Anything, "nonexistent@example.com").Return(nil, domain.ErrUserNotFound)

	req := httptest.NewRequest("POST", "/api/auth/password-reset", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.RequestPasswordReset(w, req)

	// Should still return 200 for security reasons
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthHandler_RequestPasswordReset_InternalError(t *testing.T) {
	handler, mockRepo := setupTestHandler()

	reqBody := domain.PasswordResetRequest{
		Email: "test@example.com",
	}
	body, _ := json.Marshal(reqBody)

	mockRepo.On("GetByEmail", mock.Anything, "test@example.com").Return(nil, errors.New("database error"))

	req := httptest.NewRequest("POST", "/api/auth/password-reset", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.RequestPasswordReset(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAuthHandler_ResetPassword_InvalidPayload(t *testing.T) {
	handler, _ := setupTestHandler()

	req := httptest.NewRequest("POST", "/api/auth/password-reset/confirm", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ResetPassword(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_ResetPassword_InvalidToken(t *testing.T) {
	handler, mockRepo := setupTestHandler()

	reqBody := domain.PasswordResetConfirmRequest{
		Token:    "invalid-token",
		Password: "newpassword123",
	}
	body, _ := json.Marshal(reqBody)

	mockRepo.On("GetByResetToken", mock.Anything, "invalid-token").Return(nil, domain.ErrUserNotFound)

	req := httptest.NewRequest("POST", "/api/auth/password-reset/confirm", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ResetPassword(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_ResetPassword_ExpiredToken(t *testing.T) {
	handler, mockRepo := setupTestHandler()

	reqBody := domain.PasswordResetConfirmRequest{
		Token:    "expired-token",
		Password: "newpassword123",
	}
	body, _ := json.Marshal(reqBody)

	expiredTime := time.Now().Add(-1 * time.Hour)
	user := &domain.User{
		ID:                  uuid.New(),
		Email:               "test@example.com",
		ResetTokenExpiresAt: &expiredTime,
	}
	mockRepo.On("GetByResetToken", mock.Anything, "expired-token").Return(user, nil)

	req := httptest.NewRequest("POST", "/api/auth/password-reset/confirm", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ResetPassword(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_ResetPassword_Success(t *testing.T) {
	handler, mockRepo := setupTestHandler()

	reqBody := domain.PasswordResetConfirmRequest{
		Token:    "valid-token",
		Password: "newpassword123",
	}
	body, _ := json.Marshal(reqBody)

	validTime := time.Now().Add(1 * time.Hour)
	user := &domain.User{
		ID:                  uuid.New(),
		Email:               "test@example.com",
		ResetTokenExpiresAt: &validTime,
	}
	mockRepo.On("GetByResetToken", mock.Anything, "valid-token").Return(user, nil)
	mockRepo.On("UpdatePassword", mock.Anything, user.ID, mock.AnythingOfType("string")).Return(nil)
	mockRepo.On("ClearResetToken", mock.Anything, user.ID).Return(nil)

	req := httptest.NewRequest("POST", "/api/auth/password-reset/confirm", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ResetPassword(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthHandler_ResetPassword_InternalError(t *testing.T) {
	handler, mockRepo := setupTestHandler()

	reqBody := domain.PasswordResetConfirmRequest{
		Token:    "valid-token",
		Password: "newpassword123",
	}
	body, _ := json.Marshal(reqBody)

	mockRepo.On("GetByResetToken", mock.Anything, "valid-token").Return(nil, errors.New("database error"))

	req := httptest.NewRequest("POST", "/api/auth/password-reset/confirm", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ResetPassword(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAuthHandler_VerifyEmail_InvalidPayload(t *testing.T) {
	handler, _ := setupTestHandler()

	req := httptest.NewRequest("POST", "/api/auth/verify-email", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.VerifyEmail(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_VerifyEmail_InvalidToken(t *testing.T) {
	handler, mockRepo := setupTestHandler()

	reqBody := domain.EmailVerificationRequest{
		Token: "invalid-token",
	}
	body, _ := json.Marshal(reqBody)

	mockRepo.On("GetByVerificationToken", mock.Anything, "invalid-token").Return(nil, domain.ErrUserNotFound)

	req := httptest.NewRequest("POST", "/api/auth/verify-email", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.VerifyEmail(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_VerifyEmail_ExpiredToken(t *testing.T) {
	handler, mockRepo := setupTestHandler()

	reqBody := domain.EmailVerificationRequest{
		Token: "expired-token",
	}
	body, _ := json.Marshal(reqBody)

	expiredTime := time.Now().Add(-1 * time.Hour)
	user := &domain.User{
		ID:                         uuid.New(),
		Email:                      "test@example.com",
		VerificationTokenExpiresAt: &expiredTime,
	}
	mockRepo.On("GetByVerificationToken", mock.Anything, "expired-token").Return(user, nil)

	req := httptest.NewRequest("POST", "/api/auth/verify-email", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.VerifyEmail(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_VerifyEmail_Success(t *testing.T) {
	handler, mockRepo := setupTestHandler()

	reqBody := domain.EmailVerificationRequest{
		Token: "valid-token",
	}
	body, _ := json.Marshal(reqBody)

	validTime := time.Now().Add(1 * time.Hour)
	user := &domain.User{
		ID:                         uuid.New(),
		Email:                      "test@example.com",
		VerificationTokenExpiresAt: &validTime,
	}
	mockRepo.On("GetByVerificationToken", mock.Anything, "valid-token").Return(user, nil)
	mockRepo.On("VerifyEmail", mock.Anything, user.ID).Return(nil)

	req := httptest.NewRequest("POST", "/api/auth/verify-email", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.VerifyEmail(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthHandler_VerifyEmail_InternalError(t *testing.T) {
	handler, mockRepo := setupTestHandler()

	reqBody := domain.EmailVerificationRequest{
		Token: "valid-token",
	}
	body, _ := json.Marshal(reqBody)

	mockRepo.On("GetByVerificationToken", mock.Anything, "valid-token").Return(nil, errors.New("database error"))

	req := httptest.NewRequest("POST", "/api/auth/verify-email", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.VerifyEmail(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAuthHandler_ResendVerification_InvalidPayload(t *testing.T) {
	handler, _ := setupTestHandler()

	req := httptest.NewRequest("POST", "/api/auth/resend-verification", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ResendVerification(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAuthHandler_ResendVerification_UserNotFound(t *testing.T) {
	handler, mockRepo := setupTestHandler()

	reqBody := domain.ResendVerificationRequest{
		Email: "nonexistent@example.com",
	}
	body, _ := json.Marshal(reqBody)

	mockRepo.On("GetByEmail", mock.Anything, "nonexistent@example.com").Return(nil, domain.ErrUserNotFound)

	req := httptest.NewRequest("POST", "/api/auth/resend-verification", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ResendVerification(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAuthHandler_ResendVerification_AlreadyVerified(t *testing.T) {
	handler, mockRepo := setupTestHandler()

	reqBody := domain.ResendVerificationRequest{
		Email: "test@example.com",
	}
	body, _ := json.Marshal(reqBody)

	user := &domain.User{
		ID:            uuid.New(),
		Email:         "test@example.com",
		EmailVerified: true,
	}
	mockRepo.On("GetByEmail", mock.Anything, "test@example.com").Return(user, nil)

	req := httptest.NewRequest("POST", "/api/auth/resend-verification", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ResendVerification(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthHandler_ResendVerification_Success(t *testing.T) {
	handler, mockRepo := setupTestHandler()

	reqBody := domain.ResendVerificationRequest{
		Email: "test@example.com",
	}
	body, _ := json.Marshal(reqBody)

	user := &domain.User{
		ID:            uuid.New(),
		Email:         "test@example.com",
		EmailVerified: false,
	}
	mockRepo.On("GetByEmail", mock.Anything, "test@example.com").Return(user, nil)
	mockRepo.On("UpdateVerificationToken", mock.Anything, user.ID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(nil)

	req := httptest.NewRequest("POST", "/api/auth/resend-verification", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ResendVerification(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthHandler_ResendVerification_InternalError(t *testing.T) {
	handler, mockRepo := setupTestHandler()

	reqBody := domain.ResendVerificationRequest{
		Email: "test@example.com",
	}
	body, _ := json.Marshal(reqBody)

	mockRepo.On("GetByEmail", mock.Anything, "test@example.com").Return(nil, errors.New("database error"))

	req := httptest.NewRequest("POST", "/api/auth/resend-verification", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ResendVerification(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRespondWithJSON(t *testing.T) {
	w := httptest.NewRecorder()

	respondWithJSON(w, http.StatusOK, map[string]string{"key": "value"})

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "value", response["key"])
}

func TestRespondWithError(t *testing.T) {
	w := httptest.NewRecorder()

	respondWithError(w, http.StatusBadRequest, "error message")

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var response map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "error message", response["error"])
}
