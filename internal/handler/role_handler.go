package handler

import (
	"encoding/json"
	"net/http"

	"g-auth/internal/domain"
	"g-auth/internal/middleware"
	"g-auth/internal/repository"
	"g-auth/internal/service"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type RoleHandler struct {
	roleService *service.RoleService
}

func NewRoleHandler(roleService *service.RoleService) *RoleHandler {
	return &RoleHandler{
		roleService: roleService,
	}
}

// SetupRoutes adds role management routes to the router
func (h *RoleHandler) SetupRoutes(router *mux.Router, userRepo repository.UserRepository) {
	// Admin-only routes for role management
	adminRoutes := router.PathPrefix("/api/roles").Subrouter()
	adminRoutes.Use(middleware.AuthMiddleware)
	adminRoutes.Use(func(next http.Handler) http.Handler {
		return middleware.RequireAdmin(userRepo)(next)
	})

	adminRoutes.HandleFunc("", h.CreateRole).Methods("POST")
	adminRoutes.HandleFunc("", h.GetAllRoles).Methods("GET")
	adminRoutes.HandleFunc("/{id}", h.GetRole).Methods("GET")
	adminRoutes.HandleFunc("/{id}", h.UpdateRole).Methods("PUT")
	adminRoutes.HandleFunc("/{id}", h.DeleteRole).Methods("DELETE")
	adminRoutes.HandleFunc("/assign", h.AssignRoleToUser).Methods("POST")
	adminRoutes.HandleFunc("/remove", h.RemoveRoleFromUser).Methods("POST")

	// Permissions endpoint (accessible to authenticated users)
	permRoutes := router.PathPrefix("/api/permissions").Subrouter()
	permRoutes.Use(middleware.AuthMiddleware)
	permRoutes.HandleFunc("", h.GetAllPermissions).Methods("GET")

	// User roles endpoint (accessible to authenticated users)
	userRoutes := router.PathPrefix("/api/users").Subrouter()
	userRoutes.Use(middleware.AuthMiddleware)
	userRoutes.HandleFunc("/{userId}/roles", h.GetUserRoles).Methods("GET")
}

// CreateRole handles POST /roles
func (h *RoleHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
	var req domain.CreateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	role, err := h.roleService.CreateRole(r.Context(), &req)
	if err != nil {
		if err == domain.ErrRoleAlreadyExists {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		http.Error(w, "Failed to create role", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(domain.RoleResponse{
		Role:    *role,
		Message: "Role created successfully",
	})
}

// GetRole handles GET /roles/{id}
func (h *RoleHandler) GetRole(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "Invalid role ID", http.StatusBadRequest)
		return
	}

	role, err := h.roleService.GetRole(r.Context(), id)
	if err != nil {
		if err == domain.ErrRoleNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, "Failed to get role", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(role)
}

// GetAllRoles handles GET /roles
func (h *RoleHandler) GetAllRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := h.roleService.GetAllRoles(r.Context())
	if err != nil {
		http.Error(w, "Failed to get roles", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(roles)
}

// UpdateRole handles PUT /roles/{id}
func (h *RoleHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "Invalid role ID", http.StatusBadRequest)
		return
	}

	var req domain.UpdateRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	role, err := h.roleService.UpdateRole(r.Context(), id, &req)
	if err != nil {
		if err == domain.ErrRoleNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, "Failed to update role", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(domain.RoleResponse{
		Role:    *role,
		Message: "Role updated successfully",
	})
}

// DeleteRole handles DELETE /roles/{id}
func (h *RoleHandler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	idStr := vars["id"]

	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "Invalid role ID", http.StatusBadRequest)
		return
	}

	err = h.roleService.DeleteRole(r.Context(), id)
	if err != nil {
		if err == domain.ErrRoleNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, "Failed to delete role", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Role deleted successfully",
	})
}

// GetAllPermissions handles GET /permissions
func (h *RoleHandler) GetAllPermissions(w http.ResponseWriter, r *http.Request) {
	permissions, err := h.roleService.GetAllPermissions(r.Context())
	if err != nil {
		http.Error(w, "Failed to get permissions", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(permissions)
}

// AssignRoleToUser handles POST /users/:userId/roles/:roleId
func (h *RoleHandler) AssignRoleToUser(w http.ResponseWriter, r *http.Request) {
	var req domain.AssignRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err := h.roleService.AssignRoleToUser(r.Context(), req.UserID, req.RoleID)
	if err != nil {
		if err == domain.ErrUserNotFound {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		if err == domain.ErrRoleNotFound {
			http.Error(w, "Role not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Failed to assign role to user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Role assigned to user successfully",
	})
}

// RemoveRoleFromUser handles DELETE /users/:userId/roles/:roleId
func (h *RoleHandler) RemoveRoleFromUser(w http.ResponseWriter, r *http.Request) {
	var req domain.AssignRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err := h.roleService.RemoveRoleFromUser(r.Context(), req.UserID, req.RoleID)
	if err != nil {
		if err == domain.ErrUserNotFound {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		if err == domain.ErrRoleNotFound {
			http.Error(w, "Role not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Failed to remove role from user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Role removed from user successfully",
	})
}

// RemoveRole handles POST /roles/remove
func (h *RoleHandler) RemoveRole(w http.ResponseWriter, r *http.Request) {
	var req domain.AssignRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err := h.roleService.RemoveRoleFromUser(r.Context(), req.UserID, req.RoleID)
	if err != nil {
		http.Error(w, "Failed to remove role from user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Role removed from user successfully",
	})
}

// GetUserRoles handles GET /users/{userId}/roles
func (h *RoleHandler) GetUserRoles(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userIDStr := vars["userId"]

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	roles, err := h.roleService.GetUserRoles(r.Context(), userID)
	if err != nil {
		http.Error(w, "Failed to get user roles", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(roles)
}
