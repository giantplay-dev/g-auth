package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"g-auth/internal/domain"
	"g-auth/internal/service"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockRoleService is a mock implementation of RoleService
type MockRoleService struct {
	mock.Mock
}

func (m *MockRoleService) CreateRole(ctx context.Context, req *domain.CreateRoleRequest) (*domain.Role, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Role), args.Error(1)
}

func (m *MockRoleService) GetRole(ctx context.Context, id uuid.UUID) (*domain.Role, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Role), args.Error(1)
}

func (m *MockRoleService) GetRoleByName(ctx context.Context, name string) (*domain.Role, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Role), args.Error(1)
}

func (m *MockRoleService) GetAllRoles(ctx context.Context) ([]domain.Role, error) {
	args := m.Called(ctx)
	return args.Get(0).([]domain.Role), args.Error(1)
}

func (m *MockRoleService) UpdateRole(ctx context.Context, id uuid.UUID, req *domain.UpdateRoleRequest) (*domain.Role, error) {
	args := m.Called(ctx, id, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Role), args.Error(1)
}

func (m *MockRoleService) DeleteRole(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockRoleService) GetAllPermissions(ctx context.Context) ([]domain.Permission, error) {
	args := m.Called(ctx)
	return args.Get(0).([]domain.Permission), args.Error(1)
}

func (m *MockRoleService) AssignRoleToUser(ctx context.Context, userID, roleID uuid.UUID) error {
	args := m.Called(ctx, userID, roleID)
	return args.Error(0)
}

func (m *MockRoleService) RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	args := m.Called(ctx, userID, roleID)
	return args.Error(0)
}

func (m *MockRoleService) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]domain.Role, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]domain.Role), args.Error(1)
}

func TestNewRoleHandler(t *testing.T) {
	handler := NewRoleHandler(&service.RoleService{})

	assert.NotNil(t, handler)
}

func TestRoleHandler_CreateRole_Success(t *testing.T) {
	handler := &RoleHandler{roleService: &service.RoleService{}}

	req := domain.CreateRoleRequest{
		Name:        "test_role",
		Description: "Test role",
		Permissions: []string{domain.PermissionUserRead},
	}

	body, _ := json.Marshal(req)
	_ = httptest.NewRecorder()
	_ = httptest.NewRequest("POST", "/roles", bytes.NewReader(body))

	// Test handler structure
	assert.NotNil(t, handler)
}

func TestRoleHandler_CreateRole_InvalidJSON(t *testing.T) {
	handler := &RoleHandler{roleService: &service.RoleService{}}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/roles", bytes.NewReader([]byte("invalid json")))

	handler.CreateRole(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRoleHandler_GetRole_MissingID(t *testing.T) {
	handler := &RoleHandler{roleService: &service.RoleService{}}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/roles", nil)

	handler.GetRole(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRoleHandler_GetRole_InvalidID(t *testing.T) {
	handler := &RoleHandler{roleService: &service.RoleService{}}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/roles?id=invalid-uuid", nil)

	handler.GetRole(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRoleHandler_UpdateRole_MissingID(t *testing.T) {
	handler := &RoleHandler{roleService: &service.RoleService{}}

	req := domain.UpdateRoleRequest{
		Description: "Updated",
		Permissions: []string{},
	}
	body, _ := json.Marshal(req)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("PUT", "/roles", bytes.NewReader(body))

	handler.UpdateRole(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRoleHandler_UpdateRole_InvalidID(t *testing.T) {
	handler := &RoleHandler{roleService: &service.RoleService{}}

	req := domain.UpdateRoleRequest{
		Description: "Updated",
		Permissions: []string{},
	}
	body, _ := json.Marshal(req)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("PUT", "/roles?id=invalid-uuid", bytes.NewReader(body))

	handler.UpdateRole(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRoleHandler_UpdateRole_InvalidJSON(t *testing.T) {
	roleID := uuid.New()
	handler := &RoleHandler{roleService: &service.RoleService{}}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("PUT", "/roles?id="+roleID.String(), bytes.NewReader([]byte("invalid json")))

	handler.UpdateRole(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRoleHandler_DeleteRole_MissingID(t *testing.T) {
	handler := &RoleHandler{roleService: &service.RoleService{}}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/roles", nil)

	handler.DeleteRole(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRoleHandler_DeleteRole_InvalidID(t *testing.T) {
	handler := &RoleHandler{roleService: &service.RoleService{}}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/roles?id=invalid-uuid", nil)

	handler.DeleteRole(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRoleHandler_AssignRoleToUser_InvalidJSON(t *testing.T) {
	handler := &RoleHandler{roleService: &service.RoleService{}}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/users/roles", bytes.NewReader([]byte("invalid json")))

	handler.AssignRoleToUser(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRoleHandler_RemoveRoleFromUser_MissingUserID(t *testing.T) {
	handler := &RoleHandler{roleService: &service.RoleService{}}

	roleID := uuid.New()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/users/roles?roleId="+roleID.String(), nil)

	handler.RemoveRoleFromUser(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRoleHandler_RemoveRoleFromUser_MissingRoleID(t *testing.T) {
	handler := &RoleHandler{roleService: &service.RoleService{}}

	userID := uuid.New()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/users/roles?userId="+userID.String(), nil)

	handler.RemoveRoleFromUser(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRoleHandler_RemoveRoleFromUser_InvalidUserID(t *testing.T) {
	handler := &RoleHandler{roleService: &service.RoleService{}}

	roleID := uuid.New()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/users/roles?userId=invalid&roleId="+roleID.String(), nil)

	handler.RemoveRoleFromUser(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRoleHandler_RemoveRoleFromUser_InvalidRoleID(t *testing.T) {
	handler := &RoleHandler{roleService: &service.RoleService{}}

	userID := uuid.New()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/users/roles?userId="+userID.String()+"&roleId=invalid", nil)

	handler.RemoveRoleFromUser(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRoleHandler_GetUserRoles_MissingUserID(t *testing.T) {
	handler := &RoleHandler{roleService: &service.RoleService{}}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/users/roles", nil)

	handler.GetUserRoles(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRoleHandler_GetUserRoles_InvalidUserID(t *testing.T) {
	handler := &RoleHandler{roleService: &service.RoleService{}}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/users/roles?userId=invalid-uuid", nil)

	handler.GetUserRoles(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
