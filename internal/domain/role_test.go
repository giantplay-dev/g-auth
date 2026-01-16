package domain

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestRole_HasPermission(t *testing.T) {
	role := &Role{
		ID:          uuid.New(),
		Name:        "test_role",
		Description: "Test role",
		Permissions: []Permission{
			{
				ID:       uuid.New(),
				Name:     PermissionUserRead,
				Resource: "user",
				Action:   "read",
			},
			{
				ID:       uuid.New(),
				Name:     PermissionUserWrite,
				Resource: "user",
				Action:   "write",
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	tests := []struct {
		name     string
		resource string
		action   string
		want     bool
	}{
		{
			name:     "has permission",
			resource: "user",
			action:   "read",
			want:     true,
		},
		{
			name:     "has permission write",
			resource: "user",
			action:   "write",
			want:     true,
		},
		{
			name:     "does not have permission",
			resource: "user",
			action:   "delete",
			want:     false,
		},
		{
			name:     "does not have permission - different resource",
			resource: "role",
			action:   "read",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := role.HasPermission(tt.resource, tt.action)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRole_HasPermissionByName(t *testing.T) {
	role := &Role{
		ID:          uuid.New(),
		Name:        "test_role",
		Description: "Test role",
		Permissions: []Permission{
			{
				ID:       uuid.New(),
				Name:     PermissionUserRead,
				Resource: "user",
				Action:   "read",
			},
			{
				ID:       uuid.New(),
				Name:     PermissionRoleWrite,
				Resource: "role",
				Action:   "write",
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	tests := []struct {
		name           string
		permissionName string
		want           bool
	}{
		{
			name:           "has permission by name",
			permissionName: PermissionUserRead,
			want:           true,
		},
		{
			name:           "has permission by name - role write",
			permissionName: PermissionRoleWrite,
			want:           true,
		},
		{
			name:           "does not have permission by name",
			permissionName: PermissionUserDelete,
			want:           false,
		},
		{
			name:           "does not have permission - invalid name",
			permissionName: "invalid:permission",
			want:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := role.HasPermissionByName(tt.permissionName)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRoleErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "role not found error",
			err:  ErrRoleNotFound,
			want: "role not found",
		},
		{
			name: "role already exists error",
			err:  ErrRoleAlreadyExists,
			want: "role already exists",
		},
		{
			name: "permission denied error",
			err:  ErrPermissionDenied,
			want: "permission denied",
		},
		{
			name: "invalid role error",
			err:  ErrInvalidRole,
			want: "invalid role",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.err.Error())
		})
	}
}
