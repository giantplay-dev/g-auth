package service

import (
	"context"

	"g-auth/internal/domain"
	"g-auth/internal/repository"

	"github.com/google/uuid"
)

type RoleService struct {
	roleRepo repository.RoleRepository
	userRepo repository.UserRepository
}

func NewRoleService(roleRepo repository.RoleRepository, userRepo repository.UserRepository) *RoleService {
	return &RoleService{
		roleRepo: roleRepo,
		userRepo: userRepo,
	}
}

// CreateRole creates a new role with permissions
func (s *RoleService) CreateRole(ctx context.Context, req *domain.CreateRoleRequest) (*domain.Role, error) {
	role := &domain.Role{
		Name:        req.Name,
		Description: req.Description,
	}

	err := s.roleRepo.CreateRole(ctx, role)
	if err != nil {
		return nil, err
	}

	// Assign permissions to role
	for _, permissionName := range req.Permissions {
		permission, err := s.roleRepo.GetPermissionByName(ctx, permissionName)
		if err != nil {
			continue // skip if permission doesn't exist
		}

		err = s.roleRepo.AssignPermissionToRole(ctx, role.ID, permission.ID)
		if err != nil {
			return nil, err
		}
	}

	// Reload role with permissions
	return s.roleRepo.GetRoleByID(ctx, role.ID)
}

// GetRole retrieves a role by ID
func (s *RoleService) GetRole(ctx context.Context, id uuid.UUID) (*domain.Role, error) {
	return s.roleRepo.GetRoleByID(ctx, id)
}

// GetRoleByName retrieves a role by name
func (s *RoleService) GetRoleByName(ctx context.Context, name string) (*domain.Role, error) {
	return s.roleRepo.GetRoleByName(ctx, name)
}

// GetAllRoles retrieves all roles
func (s *RoleService) GetAllRoles(ctx context.Context) ([]domain.Role, error) {
	return s.roleRepo.GetAllRoles(ctx)
}

// UpdateRole updates a role
func (s *RoleService) UpdateRole(ctx context.Context, id uuid.UUID, req *domain.UpdateRoleRequest) (*domain.Role, error) {
	role, err := s.roleRepo.GetRoleByID(ctx, id)
	if err != nil {
		return nil, err
	}

	role.Description = req.Description
	err = s.roleRepo.UpdateRole(ctx, role)
	if err != nil {
		return nil, err
	}

	// Clear existing permissions
	existingPermissions, err := s.roleRepo.GetRolePermissions(ctx, id)
	if err != nil {
		return nil, err
	}

	for _, permission := range existingPermissions {
		err = s.roleRepo.RemovePermissionFromRole(ctx, id, permission.ID)
		if err != nil {
			return nil, err
		}
	}

	// Assign new permissions
	for _, permissionName := range req.Permissions {
		permission, err := s.roleRepo.GetPermissionByName(ctx, permissionName)
		if err != nil {
			continue // skip if permission doesn't exist
		}

		err = s.roleRepo.AssignPermissionToRole(ctx, id, permission.ID)
		if err != nil {
			return nil, err
		}
	}

	// Reload role with permissions
	return s.roleRepo.GetRoleByID(ctx, id)
}

// DeleteRole deletes a role
func (s *RoleService) DeleteRole(ctx context.Context, id uuid.UUID) error {
	return s.roleRepo.DeleteRole(ctx, id)
}

// GetAllPermissions retrieves all permissions
func (s *RoleService) GetAllPermissions(ctx context.Context) ([]domain.Permission, error) {
	return s.roleRepo.GetAllPermissions(ctx)
}

// AssignRoleToUser assigns a role to a user
func (s *RoleService) AssignRoleToUser(ctx context.Context, userID, roleID uuid.UUID) error {
	// Verify user exists
	_, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	// Verify role exists
	_, err = s.roleRepo.GetRoleByID(ctx, roleID)
	if err != nil {
		return err
	}

	return s.roleRepo.AssignRoleToUser(ctx, userID, roleID)
}

// RemoveRoleFromUser removes a role from a user
func (s *RoleService) RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	return s.roleRepo.RemoveRoleFromUser(ctx, userID, roleID)
}

// GetUserRoles retrieves all roles for a user
func (s *RoleService) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]domain.Role, error) {
	return s.roleRepo.GetUserRoles(ctx, userID)
}
