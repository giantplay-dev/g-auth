# Role-Based Access Control (RBAC) Implementation

## Overview

This document describes the Role-Based Access Control (RBAC) implementation in the g-auth authentication service. RBAC provides a flexible and scalable way to manage user permissions by assigning roles to users and permissions to roles.

## Architecture

### Core Components

1. **Domain Models** (`internal/domain/role.go`)
   - `Role`: Represents a user role with associated permissions
   - `Permission`: Represents a specific permission with resource and action
   - Support methods for checking roles and permissions

2. **Database Layer** (`migrations/007_add_rbac_tables.up.sql`)
   - `roles`: Stores role definitions
   - `permissions`: Stores permission definitions
   - `user_roles`: Junction table linking users to roles
   - `role_permissions`: Junction table linking roles to permissions

3. **Repository Layer** (`internal/repository/`)
   - `RoleRepository`: Interface for role and permission data access
   - PostgreSQL implementation with full CRUD operations

4. **Service Layer** (`internal/service/role_service.go`)
   - Business logic for role management
   - Permission assignment and validation

5. **Handler Layer** (`internal/handler/role_handler.go`)
   - HTTP endpoints for role management
   - Request validation and response formatting

6. **Middleware** (`internal/middleware/rbac.go`)
   - Authentication and authorization checks
   - Role and permission verification

## Database Schema

### Roles Table
```sql
CREATE TABLE roles (
    id UUID PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
```

### Permissions Table
```sql
CREATE TABLE permissions (
    id UUID PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    resource VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    UNIQUE(resource, action)
);
```

### User Roles Junction Table
```sql
CREATE TABLE user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP,
    PRIMARY KEY (user_id, role_id)
);
```

### Role Permissions Junction Table
```sql
CREATE TABLE role_permissions (
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID REFERENCES permissions(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP,
    PRIMARY KEY (role_id, permission_id)
);
```

## Default Roles and Permissions

### Predefined Roles

1. **admin**: Administrator with full system access
   - All permissions granted

2. **user**: Standard user with basic permissions
   - `user:read` - Read user information

3. **moderator**: Moderator with elevated permissions
   - `user:read` - Read user information
   - `user:write` - Create and update users
   - `role:read` - Read role information

### Predefined Permissions

| Permission Name | Resource | Action | Description |
|----------------|----------|--------|-------------|
| `user:read` | user | read | Read user information |
| `user:write` | user | write | Create and update users |
| `user:delete` | user | delete | Delete users |
| `role:read` | role | read | Read role information |
| `role:write` | role | write | Create and update roles |
| `role:delete` | role | delete | Delete roles |
| `system:admin` | system | admin | Full system administration access |

## Usage

### Checking User Permissions

#### In Domain Layer
```go
// Check if user has a specific role
if user.HasRole(domain.RoleAdmin) {
    // User is an admin
}

// Check if user has a specific permission by resource and action
if user.HasPermission("user", "write") {
    // User can write user data
}

// Check if user has a specific permission by name
if user.HasPermissionByName(domain.PermissionUserDelete) {
    // User can delete users
}
```

#### In Middleware

```go
// Require specific role
handler := middleware.RequireRole(userRepo, domain.RoleAdmin)(yourHandler)

// Require specific permission
handler := middleware.RequirePermission(userRepo, domain.PermissionUserWrite)(yourHandler)

// Require admin role (shorthand)
handler := middleware.RequireAdmin(userRepo)(yourHandler)

// Combined auth and RBAC check
handler := middleware.AdminAuthMiddleware(userRepo)(yourHandler)
```

#### In Request Context

```go
// Check role from context
if middleware.HasRole(r.Context(), domain.RoleAdmin) {
    // User has admin role
}

// Check permission from context
if middleware.HasPermission(r.Context(), domain.PermissionUserWrite) {
    // User has write permission
}

// Get full user from context
user, err := middleware.GetUserFromContext(r.Context(), userRepo)
if err == nil {
    // Use user object
}
```

### JWT Token Integration

Roles are automatically included in JWT tokens:

```go
// Generate token with roles
token, err := jwtManager.GenerateWithRoles(user.ID, user.Email, user.GetRoleNames())
```

The JWT Claims structure includes roles:
```go
type Claims struct {
    UserID uuid.UUID `json:"user_id"`
    Email  string    `json:"email"`
    Roles  []string  `json:"roles"`
    jwt.RegisteredClaims
}
```

### Service Layer Usage

```go
roleService := service.NewRoleService(roleRepo, userRepo)

// Create a new role
role, err := roleService.CreateRole(ctx, &domain.CreateRoleRequest{
    Name:        "editor",
    Description: "Content editor role",
    Permissions: []string{"user:read", "user:write"},
})

// Assign role to user
err = roleService.AssignRoleToUser(ctx, userID, roleID)

// Get user roles
roles, err := roleService.GetUserRoles(ctx, userID)
```

## API Endpoints

### Role Management

#### Create Role
```http
POST /roles
Authorization: Bearer <admin-token>

{
  "name": "editor",
  "description": "Content editor role",
  "permissions": ["user:read", "user:write"]
}
```

**Response:**
```json
{
  "role": {
    "id": "uuid",
    "name": "editor",
    "description": "Content editor role",
    "permissions": [...],
    "created_at": "timestamp",
    "updated_at": "timestamp"
  },
  "message": "Role created successfully"
}
```

#### Get Role
```http
GET /roles?id=<role-id>
Authorization: Bearer <admin-token>
```

#### Get All Roles
```http
GET /roles
Authorization: Bearer <admin-token>
```

#### Update Role
```http
PUT /roles?id=<role-id>
Authorization: Bearer <admin-token>

{
  "description": "Updated description",
  "permissions": ["user:read", "user:write", "user:delete"]
}
```

#### Delete Role
```http
DELETE /roles?id=<role-id>
Authorization: Bearer <admin-token>
```

### Permission Management

#### Get All Permissions
```http
GET /permissions
Authorization: Bearer <admin-token>
```

### User Role Assignment

#### Assign Role to User
```http
POST /users/roles
Authorization: Bearer <admin-token>

{
  "user_id": "uuid",
  "role_id": "uuid"
}
```

#### Remove Role from User
```http
DELETE /users/roles?userId=<user-id>&roleId=<role-id>
Authorization: Bearer <admin-token>
```

#### Get User Roles
```http
GET /users/roles?userId=<user-id>
Authorization: Bearer <admin-token>
```

## Middleware Patterns

### Basic Role Check
```go
mux.Handle("/admin/dashboard", 
    middleware.AuthMiddleware(
        middleware.RequireRole(userRepo, domain.RoleAdmin)(
            http.HandlerFunc(adminDashboard),
        ),
    ),
)
```

### Permission-Based Access
```go
mux.Handle("/users", 
    middleware.AuthMiddleware(
        middleware.RequirePermission(userRepo, domain.PermissionUserWrite)(
            http.HandlerFunc(createUser),
        ),
    ),
)
```

### Combined Auth and RBAC (Shorthand)
```go
mux.Handle("/admin/settings", 
    middleware.AdminAuthMiddleware(userRepo)(
        http.HandlerFunc(adminSettings),
    ),
)
```

### Multiple Role Options
```go
mux.Handle("/moderate", 
    middleware.AuthMiddleware(
        middleware.RBACMiddleware(userRepo, 
            []string{domain.RoleAdmin, domain.RoleModerator}, 
            nil,
        )(http.HandlerFunc(moderateContent)),
    ),
)
```

## Security Considerations

1. **Principle of Least Privilege**: Assign users only the roles they need
2. **Role Hierarchy**: Admin > Moderator > User
3. **Permission Granularity**: Use specific permissions for fine-grained control
4. **Audit Trail**: All role assignments are timestamped
5. **Token Security**: Roles are embedded in JWT tokens for stateless verification

## Database Migration

Run migrations to set up RBAC tables:
```bash
# Apply RBAC migration
migrate -path migrations -database "postgresql://..." up

# Rollback RBAC migration
migrate -path migrations -database "postgresql://..." down 1
```

The migration automatically creates:
- All required tables with proper indexes
- Default roles (admin, user, moderator)
- Default permissions
- Initial permission assignments

## Best Practices

1. **Custom Roles**: Create specific roles for your application needs
2. **Permission Naming**: Use `resource:action` convention (e.g., `user:read`)
3. **Role Assignment**: Assign roles during user registration or onboarding
4. **Middleware Order**: Always apply AuthMiddleware before RBAC middleware
5. **Testing**: Test all permission combinations thoroughly
6. **Documentation**: Document custom roles and permissions

## Extension Points

### Adding Custom Roles
```go
role, err := roleService.CreateRole(ctx, &domain.CreateRoleRequest{
    Name:        "custom_role",
    Description: "Custom role for specific use case",
    Permissions: []string{"permission:name"},
})
```

### Adding Custom Permissions
```sql
INSERT INTO permissions (name, description, resource, action) 
VALUES ('custom:permission', 'Custom permission', 'custom', 'permission');
```

### Custom Middleware
```go
func RequireCustomPermission(userRepo repository.UserRepository) func(http.Handler) http.Handler {
    return middleware.RequirePermission(userRepo, "custom:permission")
}
```

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure user has the required role/permission
2. **Role Not Found**: Verify role exists in the database
3. **Migration Failed**: Check database connection and existing schema
4. **Token Missing Roles**: Regenerate token after role assignment

### Debug Commands

```sql
-- Check user roles
SELECT u.email, r.name 
FROM users u
JOIN user_roles ur ON u.id = ur.user_id
JOIN roles r ON ur.role_id = r.id
WHERE u.id = 'user-uuid';

-- Check role permissions
SELECT r.name, p.name 
FROM roles r
JOIN role_permissions rp ON r.id = rp.role_id
JOIN permissions p ON rp.permission_id = p.id
WHERE r.id = 'role-uuid';
```

## Performance Considerations

1. **Caching**: Consider caching user roles and permissions
2. **Indexes**: Proper indexes on junction tables for fast lookups
3. **N+1 Queries**: Repository loads roles with permissions in single query
4. **Token Size**: JWT tokens include roles - balance security vs. size

## Future Enhancements

- [ ] Dynamic permission creation via API
- [ ] Role hierarchy and inheritance
- [ ] Permission dependencies
- [ ] Time-based role assignments
- [ ] Role approval workflows
- [ ] Audit logging for role changes
