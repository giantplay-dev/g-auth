package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"g-auth/internal/domain"

	"github.com/google/uuid"
)

type RoleRepository struct {
	db *sql.DB
}

func NewRoleRepository(db *sql.DB) *RoleRepository {
	return &RoleRepository{db: db}
}

func isDuplicateKeyError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate key")
}

// CreateRole creates a new role
func (r *RoleRepository) CreateRole(ctx context.Context, role *domain.Role) error {
	query := `
		INSERT INTO roles (id, name, description, created_at, updated_at)
		VALUES ($1, $2, $3, NOW(), NOW())
	`

	role.ID = uuid.New()
	_, err := r.db.ExecContext(ctx, query, role.ID, role.Name, role.Description)
	if err != nil {
		if isDuplicateKeyError(err) {
			return domain.ErrRoleAlreadyExists
		}
		return err
	}

	return nil
}

// GetRoleByID retrieves a role by its ID with permissions
func (r *RoleRepository) GetRoleByID(ctx context.Context, id uuid.UUID) (*domain.Role, error) {
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM roles
		WHERE id = $1
	`

	role := &domain.Role{}
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&role.ID,
		&role.Name,
		&role.Description,
		&role.CreatedAt,
		&role.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrRoleNotFound
		}
		return nil, err
	}

	// Load permissions
	permissions, err := r.GetRolePermissions(ctx, id)
	if err != nil {
		return nil, err
	}
	role.Permissions = permissions

	return role, nil
}

// GetRoleByName retrieves a role by its name with permissions
func (r *RoleRepository) GetRoleByName(ctx context.Context, name string) (*domain.Role, error) {
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM roles
		WHERE name = $1
	`

	role := &domain.Role{}
	err := r.db.QueryRowContext(ctx, query, name).Scan(
		&role.ID,
		&role.Name,
		&role.Description,
		&role.CreatedAt,
		&role.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrRoleNotFound
		}
		return nil, err
	}

	// Load permissions
	permissions, err := r.GetRolePermissions(ctx, role.ID)
	if err != nil {
		return nil, err
	}
	role.Permissions = permissions

	return role, nil
}

// GetAllRoles retrieves all roles with their permissions
func (r *RoleRepository) GetAllRoles(ctx context.Context) ([]domain.Role, error) {
	query := `
		SELECT id, name, description, created_at, updated_at
		FROM roles
		ORDER BY name
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []domain.Role
	for rows.Next() {
		var role domain.Role
		err := rows.Scan(
			&role.ID,
			&role.Name,
			&role.Description,
			&role.CreatedAt,
			&role.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		// Load permissions for each role
		permissions, err := r.GetRolePermissions(ctx, role.ID)
		if err != nil {
			return nil, err
		}
		role.Permissions = permissions

		roles = append(roles, role)
	}

	return roles, rows.Err()
}

// UpdateRole updates a role's information
func (r *RoleRepository) UpdateRole(ctx context.Context, role *domain.Role) error {
	query := `
		UPDATE roles
		SET description = $1, updated_at = NOW()
		WHERE id = $2
	`

	result, err := r.db.ExecContext(ctx, query, role.Description, role.ID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return domain.ErrRoleNotFound
	}

	return nil
}

// DeleteRole deletes a role
func (r *RoleRepository) DeleteRole(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM roles WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return domain.ErrRoleNotFound
	}

	return nil
}

// CreatePermission creates a new permission
func (r *RoleRepository) CreatePermission(ctx context.Context, permission *domain.Permission) error {
	query := `
		INSERT INTO permissions (id, name, description, resource, action, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
	`

	permission.ID = uuid.New()
	_, err := r.db.ExecContext(ctx, query,
		permission.ID,
		permission.Name,
		permission.Description,
		permission.Resource,
		permission.Action,
	)

	if err != nil {
		if isDuplicateKeyError(err) {
			return errors.New("permission already exists")
		}
		return err
	}

	return nil
}

// GetPermissionByID retrieves a permission by its ID
func (r *RoleRepository) GetPermissionByID(ctx context.Context, id uuid.UUID) (*domain.Permission, error) {
	query := `
		SELECT id, name, description, resource, action, created_at, updated_at
		FROM permissions
		WHERE id = $1
	`

	permission := &domain.Permission{}
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&permission.ID,
		&permission.Name,
		&permission.Description,
		&permission.Resource,
		&permission.Action,
		&permission.CreatedAt,
		&permission.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("permission not found")
		}
		return nil, err
	}

	return permission, nil
}

// GetPermissionByName retrieves a permission by its name
func (r *RoleRepository) GetPermissionByName(ctx context.Context, name string) (*domain.Permission, error) {
	query := `
		SELECT id, name, description, resource, action, created_at, updated_at
		FROM permissions
		WHERE name = $1
	`

	permission := &domain.Permission{}
	err := r.db.QueryRowContext(ctx, query, name).Scan(
		&permission.ID,
		&permission.Name,
		&permission.Description,
		&permission.Resource,
		&permission.Action,
		&permission.CreatedAt,
		&permission.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("permission not found")
		}
		return nil, err
	}

	return permission, nil
}

// GetAllPermissions retrieves all permissions
func (r *RoleRepository) GetAllPermissions(ctx context.Context) ([]domain.Permission, error) {
	query := `
		SELECT id, name, description, resource, action, created_at, updated_at
		FROM permissions
		ORDER BY resource, action
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var permissions []domain.Permission
	for rows.Next() {
		var permission domain.Permission
		err := rows.Scan(
			&permission.ID,
			&permission.Name,
			&permission.Description,
			&permission.Resource,
			&permission.Action,
			&permission.CreatedAt,
			&permission.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		permissions = append(permissions, permission)
	}

	return permissions, rows.Err()
}

// DeletePermission deletes a permission
func (r *RoleRepository) DeletePermission(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM permissions WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return errors.New("permission not found")
	}

	return nil
}

// AssignPermissionToRole assigns a permission to a role
func (r *RoleRepository) AssignPermissionToRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	query := `
		INSERT INTO role_permissions (role_id, permission_id, assigned_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (role_id, permission_id) DO NOTHING
	`

	_, err := r.db.ExecContext(ctx, query, roleID, permissionID)
	return err
}

// RemovePermissionFromRole removes a permission from a role
func (r *RoleRepository) RemovePermissionFromRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	query := `
		DELETE FROM role_permissions
		WHERE role_id = $1 AND permission_id = $2
	`

	_, err := r.db.ExecContext(ctx, query, roleID, permissionID)
	return err
}

// GetRolePermissions retrieves all permissions for a role
func (r *RoleRepository) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]domain.Permission, error) {
	query := `
		SELECT p.id, p.name, p.description, p.resource, p.action, p.created_at, p.updated_at
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		WHERE rp.role_id = $1
		ORDER BY p.resource, p.action
	`

	rows, err := r.db.QueryContext(ctx, query, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var permissions []domain.Permission
	for rows.Next() {
		var permission domain.Permission
		err := rows.Scan(
			&permission.ID,
			&permission.Name,
			&permission.Description,
			&permission.Resource,
			&permission.Action,
			&permission.CreatedAt,
			&permission.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		permissions = append(permissions, permission)
	}

	return permissions, rows.Err()
}

// AssignRoleToUser assigns a role to a user
func (r *RoleRepository) AssignRoleToUser(ctx context.Context, userID, roleID uuid.UUID) error {
	query := `
		INSERT INTO user_roles (user_id, role_id, assigned_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (user_id, role_id) DO NOTHING
	`

	_, err := r.db.ExecContext(ctx, query, userID, roleID)
	return err
}

// RemoveRoleFromUser removes a role from a user
func (r *RoleRepository) RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	query := `
		DELETE FROM user_roles
		WHERE user_id = $1 AND role_id = $2
	`

	_, err := r.db.ExecContext(ctx, query, userID, roleID)
	return err
}

// GetUserRoles retrieves all roles for a user with their permissions
func (r *RoleRepository) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]domain.Role, error) {
	query := `
		SELECT r.id, r.name, r.description, r.created_at, r.updated_at
		FROM roles r
		INNER JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1
		ORDER BY r.name
	`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []domain.Role
	for rows.Next() {
		var role domain.Role
		err := rows.Scan(
			&role.ID,
			&role.Name,
			&role.Description,
			&role.CreatedAt,
			&role.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		// Load permissions for each role
		permissions, err := r.GetRolePermissions(ctx, role.ID)
		if err != nil {
			return nil, err
		}
		role.Permissions = permissions

		roles = append(roles, role)
	}

	return roles, rows.Err()
}
