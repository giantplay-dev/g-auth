package repository

import (
	"context"

	"g-auth/internal/domain"

	"github.com/google/uuid"
)

type RoleRepository interface {
	// Role operations
	CreateRole(ctx context.Context, role *domain.Role) error
	GetRoleByID(ctx context.Context, id uuid.UUID) (*domain.Role, error)
	GetRoleByName(ctx context.Context, name string) (*domain.Role, error)
	GetAllRoles(ctx context.Context) ([]domain.Role, error)
	UpdateRole(ctx context.Context, role *domain.Role) error
	DeleteRole(ctx context.Context, id uuid.UUID) error

	// Permission operations
	CreatePermission(ctx context.Context, permission *domain.Permission) error
	GetPermissionByID(ctx context.Context, id uuid.UUID) (*domain.Permission, error)
	GetPermissionByName(ctx context.Context, name string) (*domain.Permission, error)
	GetAllPermissions(ctx context.Context) ([]domain.Permission, error)
	DeletePermission(ctx context.Context, id uuid.UUID) error

	// Role-Permission operations
	AssignPermissionToRole(ctx context.Context, roleID, permissionID uuid.UUID) error
	RemovePermissionFromRole(ctx context.Context, roleID, permissionID uuid.UUID) error
	GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]domain.Permission, error)

	// User-Role operations
	AssignRoleToUser(ctx context.Context, userID, roleID uuid.UUID) error
	RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error
	GetUserRoles(ctx context.Context, userID uuid.UUID) ([]domain.Role, error)
}
