package service

import (
	"context"
	"testing"

	"g-auth/internal/domain"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockRoleRepository is a mock implementation of RoleRepository
type MockRoleRepository struct {
	mock.Mock
}

func (m *MockRoleRepository) CreateRole(ctx context.Context, role *domain.Role) error {
	args := m.Called(ctx, role)
	return args.Error(0)
}

func (m *MockRoleRepository) GetRoleByID(ctx context.Context, id uuid.UUID) (*domain.Role, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Role), args.Error(1)
}

func (m *MockRoleRepository) GetRoleByName(ctx context.Context, name string) (*domain.Role, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Role), args.Error(1)
}

func (m *MockRoleRepository) GetAllRoles(ctx context.Context) ([]domain.Role, error) {
	args := m.Called(ctx)
	return args.Get(0).([]domain.Role), args.Error(1)
}

func (m *MockRoleRepository) UpdateRole(ctx context.Context, role *domain.Role) error {
	args := m.Called(ctx, role)
	return args.Error(0)
}

func (m *MockRoleRepository) DeleteRole(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockRoleRepository) CreatePermission(ctx context.Context, permission *domain.Permission) error {
	args := m.Called(ctx, permission)
	return args.Error(0)
}

func (m *MockRoleRepository) GetPermissionByID(ctx context.Context, id uuid.UUID) (*domain.Permission, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Permission), args.Error(1)
}

func (m *MockRoleRepository) GetPermissionByName(ctx context.Context, name string) (*domain.Permission, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Permission), args.Error(1)
}

func (m *MockRoleRepository) GetAllPermissions(ctx context.Context) ([]domain.Permission, error) {
	args := m.Called(ctx)
	return args.Get(0).([]domain.Permission), args.Error(1)
}

func (m *MockRoleRepository) DeletePermission(ctx context.Context, id uuid.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockRoleRepository) AssignPermissionToRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	args := m.Called(ctx, roleID, permissionID)
	return args.Error(0)
}

func (m *MockRoleRepository) RemovePermissionFromRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	args := m.Called(ctx, roleID, permissionID)
	return args.Error(0)
}

func (m *MockRoleRepository) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]domain.Permission, error) {
	args := m.Called(ctx, roleID)
	return args.Get(0).([]domain.Permission), args.Error(1)
}

func (m *MockRoleRepository) AssignRoleToUser(ctx context.Context, userID, roleID uuid.UUID) error {
	args := m.Called(ctx, userID, roleID)
	return args.Error(0)
}

func (m *MockRoleRepository) RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	args := m.Called(ctx, userID, roleID)
	return args.Error(0)
}

func (m *MockRoleRepository) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]domain.Role, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]domain.Role), args.Error(1)
}

func TestNewRoleService(t *testing.T) {
	mockRoleRepo := new(MockRoleRepository)
	mockUserRepo := new(MockUserRepository)

	service := NewRoleService(mockRoleRepo, mockUserRepo)

	assert.NotNil(t, service)
}

func TestRoleService_CreateRole(t *testing.T) {
	mockRoleRepo := new(MockRoleRepository)
	mockUserRepo := new(MockUserRepository)
	service := NewRoleService(mockRoleRepo, mockUserRepo)

	req := &domain.CreateRoleRequest{
		Name:        "test_role",
		Description: "Test role",
		Permissions: []string{domain.PermissionUserRead},
	}

	roleID := uuid.New()
	permission := &domain.Permission{
		ID:   uuid.New(),
		Name: domain.PermissionUserRead,
	}

	createdRole := &domain.Role{
		ID:          roleID,
		Name:        req.Name,
		Description: req.Description,
		Permissions: []domain.Permission{*permission},
	}

	mockRoleRepo.On("CreateRole", mock.Anything, mock.AnythingOfType("*domain.Role")).Return(nil)
	mockRoleRepo.On("GetPermissionByName", mock.Anything, domain.PermissionUserRead).Return(permission, nil)
	mockRoleRepo.On("AssignPermissionToRole", mock.Anything, mock.AnythingOfType("uuid.UUID"), permission.ID).Return(nil)
	mockRoleRepo.On("GetRoleByID", mock.Anything, mock.AnythingOfType("uuid.UUID")).Return(createdRole, nil)

	role, err := service.CreateRole(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, role)
	assert.Equal(t, req.Name, role.Name)
	mockRoleRepo.AssertExpectations(t)
}

func TestRoleService_CreateRole_AlreadyExists(t *testing.T) {
	mockRoleRepo := new(MockRoleRepository)
	mockUserRepo := new(MockUserRepository)
	service := NewRoleService(mockRoleRepo, mockUserRepo)

	req := &domain.CreateRoleRequest{
		Name:        "test_role",
		Description: "Test role",
	}

	mockRoleRepo.On("CreateRole", mock.Anything, mock.AnythingOfType("*domain.Role")).Return(domain.ErrRoleAlreadyExists)

	role, err := service.CreateRole(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, role)
	assert.Equal(t, domain.ErrRoleAlreadyExists, err)
	mockRoleRepo.AssertExpectations(t)
}

func TestRoleService_GetRole(t *testing.T) {
	mockRoleRepo := new(MockRoleRepository)
	mockUserRepo := new(MockUserRepository)
	service := NewRoleService(mockRoleRepo, mockUserRepo)

	roleID := uuid.New()
	expectedRole := &domain.Role{
		ID:          roleID,
		Name:        "test_role",
		Description: "Test role",
	}

	mockRoleRepo.On("GetRoleByID", mock.Anything, roleID).Return(expectedRole, nil)

	role, err := service.GetRole(context.Background(), roleID)

	assert.NoError(t, err)
	assert.Equal(t, expectedRole, role)
	mockRoleRepo.AssertExpectations(t)
}

func TestRoleService_GetRole_NotFound(t *testing.T) {
	mockRoleRepo := new(MockRoleRepository)
	mockUserRepo := new(MockUserRepository)
	service := NewRoleService(mockRoleRepo, mockUserRepo)

	roleID := uuid.New()
	mockRoleRepo.On("GetRoleByID", mock.Anything, roleID).Return(nil, domain.ErrRoleNotFound)

	role, err := service.GetRole(context.Background(), roleID)

	assert.Error(t, err)
	assert.Nil(t, role)
	assert.Equal(t, domain.ErrRoleNotFound, err)
	mockRoleRepo.AssertExpectations(t)
}

func TestRoleService_GetAllRoles(t *testing.T) {
	mockRoleRepo := new(MockRoleRepository)
	mockUserRepo := new(MockUserRepository)
	service := NewRoleService(mockRoleRepo, mockUserRepo)

	expectedRoles := []domain.Role{
		{ID: uuid.New(), Name: "role1"},
		{ID: uuid.New(), Name: "role2"},
	}

	mockRoleRepo.On("GetAllRoles", mock.Anything).Return(expectedRoles, nil)

	roles, err := service.GetAllRoles(context.Background())

	assert.NoError(t, err)
	assert.Len(t, roles, 2)
	mockRoleRepo.AssertExpectations(t)
}

func TestRoleService_UpdateRole(t *testing.T) {
	mockRoleRepo := new(MockRoleRepository)
	mockUserRepo := new(MockUserRepository)
	service := NewRoleService(mockRoleRepo, mockUserRepo)

	roleID := uuid.New()
	req := &domain.UpdateRoleRequest{
		Description: "Updated description",
		Permissions: []string{domain.PermissionUserWrite},
	}

	existingRole := &domain.Role{
		ID:          roleID,
		Name:        "test_role",
		Description: "Old description",
	}

	permission := &domain.Permission{
		ID:   uuid.New(),
		Name: domain.PermissionUserWrite,
	}

	updatedRole := &domain.Role{
		ID:          roleID,
		Name:        "test_role",
		Description: req.Description,
		Permissions: []domain.Permission{*permission},
	}

	mockRoleRepo.On("GetRoleByID", mock.Anything, roleID).Return(existingRole, nil).Once()
	mockRoleRepo.On("UpdateRole", mock.Anything, mock.AnythingOfType("*domain.Role")).Return(nil)
	mockRoleRepo.On("GetRolePermissions", mock.Anything, roleID).Return([]domain.Permission{}, nil)
	mockRoleRepo.On("GetPermissionByName", mock.Anything, domain.PermissionUserWrite).Return(permission, nil)
	mockRoleRepo.On("AssignPermissionToRole", mock.Anything, roleID, permission.ID).Return(nil)
	mockRoleRepo.On("GetRoleByID", mock.Anything, roleID).Return(updatedRole, nil).Once()

	role, err := service.UpdateRole(context.Background(), roleID, req)

	assert.NoError(t, err)
	assert.NotNil(t, role)
	assert.Equal(t, req.Description, role.Description)
	mockRoleRepo.AssertExpectations(t)
}

func TestRoleService_DeleteRole(t *testing.T) {
	mockRoleRepo := new(MockRoleRepository)
	mockUserRepo := new(MockUserRepository)
	service := NewRoleService(mockRoleRepo, mockUserRepo)

	roleID := uuid.New()
	mockRoleRepo.On("DeleteRole", mock.Anything, roleID).Return(nil)

	err := service.DeleteRole(context.Background(), roleID)

	assert.NoError(t, err)
	mockRoleRepo.AssertExpectations(t)
}

func TestRoleService_GetAllPermissions(t *testing.T) {
	mockRoleRepo := new(MockRoleRepository)
	mockUserRepo := new(MockUserRepository)
	service := NewRoleService(mockRoleRepo, mockUserRepo)

	expectedPermissions := []domain.Permission{
		{ID: uuid.New(), Name: domain.PermissionUserRead},
		{ID: uuid.New(), Name: domain.PermissionUserWrite},
	}

	mockRoleRepo.On("GetAllPermissions", mock.Anything).Return(expectedPermissions, nil)

	permissions, err := service.GetAllPermissions(context.Background())

	assert.NoError(t, err)
	assert.Len(t, permissions, 2)
	mockRoleRepo.AssertExpectations(t)
}

func TestRoleService_AssignRoleToUser(t *testing.T) {
	mockRoleRepo := new(MockRoleRepository)
	mockUserRepo := new(MockUserRepository)
	service := NewRoleService(mockRoleRepo, mockUserRepo)

	userID := uuid.New()
	roleID := uuid.New()

	user := &domain.User{ID: userID}
	role := &domain.Role{ID: roleID}

	mockUserRepo.On("GetByID", mock.Anything, userID).Return(user, nil)
	mockRoleRepo.On("GetRoleByID", mock.Anything, roleID).Return(role, nil)
	mockRoleRepo.On("AssignRoleToUser", mock.Anything, userID, roleID).Return(nil)

	err := service.AssignRoleToUser(context.Background(), userID, roleID)

	assert.NoError(t, err)
	mockUserRepo.AssertExpectations(t)
	mockRoleRepo.AssertExpectations(t)
}

func TestRoleService_AssignRoleToUser_UserNotFound(t *testing.T) {
	mockRoleRepo := new(MockRoleRepository)
	mockUserRepo := new(MockUserRepository)
	service := NewRoleService(mockRoleRepo, mockUserRepo)

	userID := uuid.New()
	roleID := uuid.New()

	mockUserRepo.On("GetByID", mock.Anything, userID).Return(nil, domain.ErrUserNotFound)

	err := service.AssignRoleToUser(context.Background(), userID, roleID)

	assert.Error(t, err)
	assert.Equal(t, domain.ErrUserNotFound, err)
	mockUserRepo.AssertExpectations(t)
}

func TestRoleService_RemoveRoleFromUser(t *testing.T) {
	mockRoleRepo := new(MockRoleRepository)
	mockUserRepo := new(MockUserRepository)
	service := NewRoleService(mockRoleRepo, mockUserRepo)

	userID := uuid.New()
	roleID := uuid.New()

	mockRoleRepo.On("RemoveRoleFromUser", mock.Anything, userID, roleID).Return(nil)

	err := service.RemoveRoleFromUser(context.Background(), userID, roleID)

	assert.NoError(t, err)
	mockRoleRepo.AssertExpectations(t)
}

func TestRoleService_GetUserRoles(t *testing.T) {
	mockRoleRepo := new(MockRoleRepository)
	mockUserRepo := new(MockUserRepository)
	service := NewRoleService(mockRoleRepo, mockUserRepo)

	userID := uuid.New()
	expectedRoles := []domain.Role{
		{ID: uuid.New(), Name: domain.RoleAdmin},
		{ID: uuid.New(), Name: domain.RoleUser},
	}

	mockRoleRepo.On("GetUserRoles", mock.Anything, userID).Return(expectedRoles, nil)

	roles, err := service.GetUserRoles(context.Background(), userID)

	assert.NoError(t, err)
	assert.Len(t, roles, 2)
	mockRoleRepo.AssertExpectations(t)
}
