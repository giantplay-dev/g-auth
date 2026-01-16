package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"g-auth/internal/domain"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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

func TestRBACMiddleware_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userID := uuid.New()

	user := &domain.User{
		ID:    userID,
		Email: "test@example.com",
		Roles: []domain.Role{
			{
				Name: domain.RoleAdmin,
				Permissions: []domain.Permission{
					{Name: domain.PermissionUserRead},
					{Name: domain.PermissionUserWrite},
				},
			},
		},
	}

	mockRepo.On("GetByID", mock.Anything, userID).Return(user, nil)

	handler := RBACMiddleware(mockRepo, []string{domain.RoleAdmin}, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	ctx := context.WithValue(req.Context(), UserIDKey, userID)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockRepo.AssertExpectations(t)
}

func TestRBACMiddleware_NoUserID(t *testing.T) {
	mockRepo := new(MockUserRepository)

	handler := RBACMiddleware(mockRepo, []string{domain.RoleAdmin}, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRBACMiddleware_UserNotFound(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userID := uuid.New()

	mockRepo.On("GetByID", mock.Anything, userID).Return(nil, domain.ErrUserNotFound)

	handler := RBACMiddleware(mockRepo, []string{domain.RoleAdmin}, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	ctx := context.WithValue(req.Context(), UserIDKey, userID)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	mockRepo.AssertExpectations(t)
}

func TestRBACMiddleware_InsufficientRole(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userID := uuid.New()

	user := &domain.User{
		ID:    userID,
		Email: "test@example.com",
		Roles: []domain.Role{
			{Name: domain.RoleUser},
		},
	}

	mockRepo.On("GetByID", mock.Anything, userID).Return(user, nil)

	handler := RBACMiddleware(mockRepo, []string{domain.RoleAdmin}, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	ctx := context.WithValue(req.Context(), UserIDKey, userID)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	mockRepo.AssertExpectations(t)
}

func TestRBACMiddleware_InsufficientPermission(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userID := uuid.New()

	user := &domain.User{
		ID:    userID,
		Email: "test@example.com",
		Roles: []domain.Role{
			{
				Name: domain.RoleUser,
				Permissions: []domain.Permission{
					{Name: domain.PermissionUserRead},
				},
			},
		},
	}

	mockRepo.On("GetByID", mock.Anything, userID).Return(user, nil)

	handler := RBACMiddleware(mockRepo, nil, []string{domain.PermissionUserWrite})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	ctx := context.WithValue(req.Context(), UserIDKey, userID)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	mockRepo.AssertExpectations(t)
}

func TestRequireRole(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userID := uuid.New()

	user := &domain.User{
		ID:    userID,
		Email: "test@example.com",
		Roles: []domain.Role{
			{Name: domain.RoleAdmin},
		},
	}

	mockRepo.On("GetByID", mock.Anything, userID).Return(user, nil)

	handler := RequireRole(mockRepo, domain.RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	ctx := context.WithValue(req.Context(), UserIDKey, userID)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockRepo.AssertExpectations(t)
}

func TestRequirePermission(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userID := uuid.New()

	user := &domain.User{
		ID:    userID,
		Email: "test@example.com",
		Roles: []domain.Role{
			{
				Name: domain.RoleUser,
				Permissions: []domain.Permission{
					{Name: domain.PermissionUserRead},
				},
			},
		},
	}

	mockRepo.On("GetByID", mock.Anything, userID).Return(user, nil)

	handler := RequirePermission(mockRepo, domain.PermissionUserRead)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	ctx := context.WithValue(req.Context(), UserIDKey, userID)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockRepo.AssertExpectations(t)
}

func TestRequireAdmin(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userID := uuid.New()

	user := &domain.User{
		ID:    userID,
		Email: "admin@example.com",
		Roles: []domain.Role{
			{Name: domain.RoleAdmin},
		},
	}

	mockRepo.On("GetByID", mock.Anything, userID).Return(user, nil)

	handler := RequireAdmin(mockRepo)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	ctx := context.WithValue(req.Context(), UserIDKey, userID)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockRepo.AssertExpectations(t)
}

func TestGetUserFromContext(t *testing.T) {
	mockRepo := new(MockUserRepository)
	userID := uuid.New()

	user := &domain.User{
		ID:    userID,
		Email: "test@example.com",
	}

	mockRepo.On("GetByID", mock.Anything, userID).Return(user, nil)

	ctx := context.WithValue(context.Background(), UserIDKey, userID)
	result, err := GetUserFromContext(ctx, mockRepo)

	assert.NoError(t, err)
	assert.Equal(t, user, result)
	mockRepo.AssertExpectations(t)
}

func TestGetUserFromContext_NoUserID(t *testing.T) {
	mockRepo := new(MockUserRepository)
	ctx := context.Background()

	result, err := GetUserFromContext(ctx, mockRepo)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, domain.ErrPermissionDenied, err)
}

func TestHasRole(t *testing.T) {
	ctx := context.WithValue(context.Background(), RolesKey, []string{domain.RoleAdmin, domain.RoleUser})

	assert.True(t, HasRole(ctx, domain.RoleAdmin))
	assert.True(t, HasRole(ctx, domain.RoleUser))
	assert.False(t, HasRole(ctx, domain.RoleModerator))
}

func TestHasRole_NoRoles(t *testing.T) {
	ctx := context.Background()

	assert.False(t, HasRole(ctx, domain.RoleAdmin))
}

func TestHasPermission(t *testing.T) {
	roles := []domain.Role{
		{
			Name: domain.RoleAdmin,
			Permissions: []domain.Permission{
				{Name: domain.PermissionUserRead},
				{Name: domain.PermissionUserWrite},
			},
		},
	}

	ctx := context.WithValue(context.Background(), PermissionsKey, roles)

	assert.True(t, HasPermission(ctx, domain.PermissionUserRead))
	assert.True(t, HasPermission(ctx, domain.PermissionUserWrite))
	assert.False(t, HasPermission(ctx, domain.PermissionUserDelete))
}

func TestHasPermission_NoPermissions(t *testing.T) {
	ctx := context.Background()

	assert.False(t, HasPermission(ctx, domain.PermissionUserRead))
}
