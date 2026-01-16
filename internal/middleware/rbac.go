package middleware

import (
	"context"
	"net/http"

	"g-auth/internal/domain"
	"g-auth/internal/repository"

	"github.com/google/uuid"
)

const RolesKey contextKey = "roles"
const PermissionsKey contextKey = "permissions"

// RBACMiddleware checks if the user has the required roles or permissions
func RBACMiddleware(userRepo repository.UserRepository, requiredRoles []string, requiredPermissions []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get user ID from context (set by AuthMiddleware)
			userID, ok := r.Context().Value(UserIDKey).(uuid.UUID)
			if !ok {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Fetch user with roles
			user, err := userRepo.GetByID(r.Context(), userID)
			if err != nil {
				http.Error(w, "User not found", http.StatusUnauthorized)
				return
			}

			// Check required roles
			if len(requiredRoles) > 0 {
				hasRole := false
				for _, requiredRole := range requiredRoles {
					if user.HasRole(requiredRole) {
						hasRole = true
						break
					}
				}
				if !hasRole {
					http.Error(w, "Forbidden: insufficient role permissions", http.StatusForbidden)
					return
				}
			}

			// Check required permissions
			if len(requiredPermissions) > 0 {
				hasPermission := false
				for _, requiredPermission := range requiredPermissions {
					if user.HasPermissionByName(requiredPermission) {
						hasPermission = true
						break
					}
				}
				if !hasPermission {
					http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
					return
				}
			}

			// Add roles and permissions to context
			ctx := context.WithValue(r.Context(), RolesKey, user.GetRoleNames())
			ctx = context.WithValue(ctx, PermissionsKey, user.Roles)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole creates middleware that requires specific roles
func RequireRole(userRepo repository.UserRepository, roles ...string) func(http.Handler) http.Handler {
	return RBACMiddleware(userRepo, roles, nil)
}

// RequirePermission creates middleware that requires specific permissions
func RequirePermission(userRepo repository.UserRepository, permissions ...string) func(http.Handler) http.Handler {
	return RBACMiddleware(userRepo, nil, permissions)
}

// RequireAdmin creates middleware that requires admin role
func RequireAdmin(userRepo repository.UserRepository) func(http.Handler) http.Handler {
	return RequireRole(userRepo, domain.RoleAdmin)
}

// RBACAuthMiddleware combines authentication and RBAC checks
func RBACAuthMiddleware(userRepo repository.UserRepository, requiredRoles []string, requiredPermissions []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return AuthMiddleware(RBACMiddleware(userRepo, requiredRoles, requiredPermissions)(next))
	}
}

// AdminAuthMiddleware combines authentication and admin role check
func AdminAuthMiddleware(userRepo repository.UserRepository) func(http.Handler) http.Handler {
	return RBACAuthMiddleware(userRepo, []string{domain.RoleAdmin}, nil)
}

// GetUserFromContext retrieves user information from context
func GetUserFromContext(ctx context.Context, userRepo repository.UserRepository) (*domain.User, error) {
	userID, ok := ctx.Value(UserIDKey).(uuid.UUID)
	if !ok {
		return nil, domain.ErrPermissionDenied
	}

	return userRepo.GetByID(ctx, userID)
}

// HasRole checks if the current user has a specific role
func HasRole(ctx context.Context, roleName string) bool {
	roles, ok := ctx.Value(RolesKey).([]string)
	if !ok {
		return false
	}

	for _, role := range roles {
		if role == roleName {
			return true
		}
	}
	return false
}

// HasPermission checks if the current user has a specific permission
func HasPermission(ctx context.Context, permissionName string) bool {
	roles, ok := ctx.Value(PermissionsKey).([]domain.Role)
	if !ok {
		return false
	}

	for _, role := range roles {
		if role.HasPermissionByName(permissionName) {
			return true
		}
	}
	return false
}
