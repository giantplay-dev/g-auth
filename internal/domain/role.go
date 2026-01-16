package domain

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrRoleNotFound      = errors.New("role not found")
	ErrRoleAlreadyExists = errors.New("role already exists")
	ErrPermissionDenied  = errors.New("permission denied")
	ErrInvalidRole       = errors.New("invalid role")
)

// Role represents a user role in the system
type Role struct {
	ID          uuid.UUID    `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

// Permission represents a specific permission that can be granted to a role
type Permission struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Resource    string    `json:"resource"`
	Action      string    `json:"action"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// CreateRoleRequest represents the request to create a new role
type CreateRoleRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"` // permission names
}

// UpdateRoleRequest represents the request to update a role
type UpdateRoleRequest struct {
	Description string   `json:"description"`
	Permissions []string `json:"permissions"` // permission names
}

// AssignRoleRequest represents the request to assign a role to a user
type AssignRoleRequest struct {
	UserID uuid.UUID `json:"user_id"`
	RoleID uuid.UUID `json:"role_id"`
}

// RoleResponse represents the response for role operations
type RoleResponse struct {
	Role    Role   `json:"role"`
	Message string `json:"message,omitempty"`
}

// HasPermission checks if a role has a specific permission
func (r *Role) HasPermission(resource, action string) bool {
	for _, p := range r.Permissions {
		if p.Resource == resource && p.Action == action {
			return true
		}
	}
	return false
}

// HasPermissionByName checks if a role has a specific permission by name
func (r *Role) HasPermissionByName(permissionName string) bool {
	for _, p := range r.Permissions {
		if p.Name == permissionName {
			return true
		}
	}
	return false
}

// Predefined role names
const (
	RoleAdmin     = "admin"
	RoleUser      = "user"
	RoleModerator = "moderator"
)

// Predefined permissions
const (
	// User permissions
	PermissionUserRead   = "user:read"
	PermissionUserWrite  = "user:write"
	PermissionUserDelete = "user:delete"

	// Role permissions
	PermissionRoleRead   = "role:read"
	PermissionRoleWrite  = "role:write"
	PermissionRoleDelete = "role:delete"

	// System permissions
	PermissionSystemAdmin = "system:admin"
)
