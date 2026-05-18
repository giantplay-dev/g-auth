package e2e_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"g-auth/internal/config"
	"g-auth/internal/domain"
	"g-auth/internal/handler"
	"g-auth/internal/middleware"
	"g-auth/internal/service"
	"g-auth/pkg/jwt"
	"g-auth/pkg/mailer"
)

const testJWTSecret = "e2e-test-secret-key"

var errPermissionNotFound = errors.New("permission not found")

// TestMain sets JWT_SECRET so the AuthMiddleware (which reads from config.Load())
// uses the same secret as the service under test.
func TestMain(m *testing.M) {
	os.Setenv("JWT_SECRET", testJWTSecret)
	os.Exit(m.Run())
}

// ----- In-Memory User Repository -----

type InMemUserRepo struct {
	mu    sync.RWMutex
	users map[uuid.UUID]*domain.User
}

func newInMemUserRepo() *InMemUserRepo {
	return &InMemUserRepo{users: make(map[uuid.UUID]*domain.User)}
}

func (r *InMemUserRepo) Create(ctx context.Context, user *domain.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if user.ID == uuid.Nil {
		user.ID = uuid.New()
	}
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	cp := *user
	r.users[user.ID] = &cp
	return nil
}

func (r *InMemUserRepo) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, u := range r.users {
		if u.Email == email {
			cp := *u
			return &cp, nil
		}
	}
	return nil, domain.ErrUserNotFound
}

func (r *InMemUserRepo) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	u, ok := r.users[id]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	cp := *u
	return &cp, nil
}

func (r *InMemUserRepo) UpdateResetToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return domain.ErrUserNotFound
	}
	u.ResetToken = &token
	u.ResetTokenExpiresAt = &expiresAt
	return nil
}

func (r *InMemUserRepo) GetByResetToken(ctx context.Context, token string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, u := range r.users {
		if u.ResetToken != nil && *u.ResetToken == token {
			cp := *u
			return &cp, nil
		}
	}
	return nil, domain.ErrUserNotFound
}

func (r *InMemUserRepo) UpdatePassword(ctx context.Context, userID uuid.UUID, hashedPassword string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return domain.ErrUserNotFound
	}
	u.Password = hashedPassword
	return nil
}

func (r *InMemUserRepo) ClearResetToken(ctx context.Context, userID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return domain.ErrUserNotFound
	}
	u.ResetToken = nil
	u.ResetTokenExpiresAt = nil
	return nil
}

func (r *InMemUserRepo) UpdateRefreshToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return domain.ErrUserNotFound
	}
	u.RefreshToken = &token
	u.RefreshTokenExpiresAt = &expiresAt
	return nil
}

func (r *InMemUserRepo) GetByRefreshToken(ctx context.Context, token string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, u := range r.users {
		if u.RefreshToken != nil && *u.RefreshToken == token {
			cp := *u
			return &cp, nil
		}
	}
	return nil, domain.ErrUserNotFound
}

func (r *InMemUserRepo) ClearRefreshToken(ctx context.Context, userID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return domain.ErrUserNotFound
	}
	u.RefreshToken = nil
	u.RefreshTokenExpiresAt = nil
	return nil
}

func (r *InMemUserRepo) UpdateVerificationToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return domain.ErrUserNotFound
	}
	u.VerificationToken = &token
	u.VerificationTokenExpiresAt = &expiresAt
	return nil
}

func (r *InMemUserRepo) GetByVerificationToken(ctx context.Context, token string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, u := range r.users {
		if u.VerificationToken != nil && *u.VerificationToken == token {
			cp := *u
			return &cp, nil
		}
	}
	return nil, domain.ErrUserNotFound
}

func (r *InMemUserRepo) VerifyEmail(ctx context.Context, userID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return domain.ErrUserNotFound
	}
	u.EmailVerified = true
	u.VerificationToken = nil
	u.VerificationTokenExpiresAt = nil
	return nil
}

func (r *InMemUserRepo) IncrementFailedAttempts(ctx context.Context, userID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return domain.ErrUserNotFound
	}
	u.FailedAttempts++
	return nil
}

func (r *InMemUserRepo) ResetFailedAttempts(ctx context.Context, userID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return domain.ErrUserNotFound
	}
	u.FailedAttempts = 0
	return nil
}

func (r *InMemUserRepo) LockAccount(ctx context.Context, userID uuid.UUID, lockedUntil time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return domain.ErrUserNotFound
	}
	u.IsLocked = true
	u.LockedUntil = &lockedUntil
	return nil
}

func (r *InMemUserRepo) UnlockAccount(ctx context.Context, userID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return domain.ErrUserNotFound
	}
	u.IsLocked = false
	u.LockedUntil = nil
	u.FailedAttempts = 0
	return nil
}

func (r *InMemUserRepo) UpdateMFACode(ctx context.Context, userID uuid.UUID, code string, expiresAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return domain.ErrUserNotFound
	}
	u.MFACode = &code
	u.MFACodeExpiresAt = &expiresAt
	return nil
}

func (r *InMemUserRepo) ClearMFACode(ctx context.Context, userID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return domain.ErrUserNotFound
	}
	u.MFACode = nil
	u.MFACodeExpiresAt = nil
	return nil
}

func (r *InMemUserRepo) EnableMFA(ctx context.Context, userID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return domain.ErrUserNotFound
	}
	u.MFAEnabled = true
	return nil
}

func (r *InMemUserRepo) DisableMFA(ctx context.Context, userID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[userID]
	if !ok {
		return domain.ErrUserNotFound
	}
	u.MFAEnabled = false
	return nil
}

// GetUserByEmail is a test-only helper to inspect stored user state.
func (r *InMemUserRepo) GetUserByEmail(email string) *domain.User {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, u := range r.users {
		if u.Email == email {
			cp := *u
			return &cp
		}
	}
	return nil
}

// ----- In-Memory Role Repository -----

type InMemRoleRepo struct {
	mu          sync.RWMutex
	roles       map[uuid.UUID]*domain.Role
	permissions map[uuid.UUID]*domain.Permission
	userRoles   map[uuid.UUID][]uuid.UUID // userID → roleIDs
	rolePerms   map[uuid.UUID][]uuid.UUID // roleID → permissionIDs
}

func newInMemRoleRepo() *InMemRoleRepo {
	return &InMemRoleRepo{
		roles:       make(map[uuid.UUID]*domain.Role),
		permissions: make(map[uuid.UUID]*domain.Permission),
		userRoles:   make(map[uuid.UUID][]uuid.UUID),
		rolePerms:   make(map[uuid.UUID][]uuid.UUID),
	}
}

func (r *InMemRoleRepo) CreateRole(ctx context.Context, role *domain.Role) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if role.ID == uuid.Nil {
		role.ID = uuid.New()
	}
	cp := *role
	r.roles[role.ID] = &cp
	return nil
}

func (r *InMemRoleRepo) GetRoleByID(ctx context.Context, id uuid.UUID) (*domain.Role, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	role, ok := r.roles[id]
	if !ok {
		return nil, domain.ErrRoleNotFound
	}
	cp := *role
	return &cp, nil
}

func (r *InMemRoleRepo) GetRoleByName(ctx context.Context, name string) (*domain.Role, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, role := range r.roles {
		if role.Name == name {
			cp := *role
			return &cp, nil
		}
	}
	return nil, domain.ErrRoleNotFound
}

func (r *InMemRoleRepo) GetAllRoles(ctx context.Context) ([]domain.Role, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]domain.Role, 0, len(r.roles))
	for _, role := range r.roles {
		result = append(result, *role)
	}
	return result, nil
}

func (r *InMemRoleRepo) UpdateRole(ctx context.Context, role *domain.Role) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.roles[role.ID]; !ok {
		return domain.ErrRoleNotFound
	}
	cp := *role
	r.roles[role.ID] = &cp
	return nil
}

func (r *InMemRoleRepo) DeleteRole(ctx context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.roles, id)
	return nil
}

func (r *InMemRoleRepo) CreatePermission(ctx context.Context, perm *domain.Permission) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if perm.ID == uuid.Nil {
		perm.ID = uuid.New()
	}
	cp := *perm
	r.permissions[perm.ID] = &cp
	return nil
}

func (r *InMemRoleRepo) GetPermissionByID(ctx context.Context, id uuid.UUID) (*domain.Permission, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.permissions[id]
	if !ok {
		return nil, errPermissionNotFound
	}
	cp := *p
	return &cp, nil
}

func (r *InMemRoleRepo) GetPermissionByName(ctx context.Context, name string) (*domain.Permission, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, p := range r.permissions {
		if p.Name == name {
			cp := *p
			return &cp, nil
		}
	}
	return nil, errPermissionNotFound
}

func (r *InMemRoleRepo) GetAllPermissions(ctx context.Context) ([]domain.Permission, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]domain.Permission, 0, len(r.permissions))
	for _, p := range r.permissions {
		result = append(result, *p)
	}
	return result, nil
}

func (r *InMemRoleRepo) DeletePermission(ctx context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.permissions, id)
	return nil
}

func (r *InMemRoleRepo) AssignPermissionToRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rolePerms[roleID] = append(r.rolePerms[roleID], permissionID)
	return nil
}

func (r *InMemRoleRepo) RemovePermissionFromRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	perms := r.rolePerms[roleID]
	updated := perms[:0]
	for _, id := range perms {
		if id != permissionID {
			updated = append(updated, id)
		}
	}
	r.rolePerms[roleID] = updated
	return nil
}

func (r *InMemRoleRepo) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]domain.Permission, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	permIDs := r.rolePerms[roleID]
	result := make([]domain.Permission, 0, len(permIDs))
	for _, pid := range permIDs {
		if p, ok := r.permissions[pid]; ok {
			result = append(result, *p)
		}
	}
	return result, nil
}

func (r *InMemRoleRepo) AssignRoleToUser(ctx context.Context, userID, roleID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.userRoles[userID] = append(r.userRoles[userID], roleID)
	return nil
}

func (r *InMemRoleRepo) RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	roles := r.userRoles[userID]
	updated := roles[:0]
	for _, id := range roles {
		if id != roleID {
			updated = append(updated, id)
		}
	}
	r.userRoles[userID] = updated
	return nil
}

func (r *InMemRoleRepo) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]domain.Role, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	roleIDs := r.userRoles[userID]
	result := make([]domain.Role, 0, len(roleIDs))
	for _, rid := range roleIDs {
		if role, ok := r.roles[rid]; ok {
			result = append(result, *role)
		}
	}
	return result, nil
}

// ----- Test Server Setup -----

type testEnv struct {
	server   *httptest.Server
	userRepo *InMemUserRepo
	roleRepo *InMemRoleRepo
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	userRepo := newInMemUserRepo()
	roleRepo := newInMemRoleRepo()

	jwtManager := jwt.NewJWTManager(testJWTSecret, time.Hour, 7*24*time.Hour)
	noopMailer := mailer.NewNoOpMailer()

	authService := service.NewAuthService(userRepo, jwtManager, noopMailer)
	authService.SetRoleRepository(roleRepo)
	roleService := service.NewRoleService(roleRepo, userRepo)

	authHandler := handler.NewAuthHandler(authService)
	roleHandler := handler.NewRoleHandler(roleService)

	router := authHandler.SetupRoutes()
	roleHandler.SetupRoutes(router, userRepo)

	cfg := &config.Config{
		RateLimit:      10000,
		RateLimitBurst: 20000,
	}
	router.Use(middleware.RateLimitMiddleware(cfg))
	router.Use(middleware.TraceMiddleware)

	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	return &testEnv{
		server:   srv,
		userRepo: userRepo,
		roleRepo: roleRepo,
	}
}
