package handler

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"g-auth/internal/domain"
	"g-auth/internal/middleware"
	"g-auth/internal/service"
)

type AuthHandler struct {
	authService *service.AuthService
}

func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

func (h *AuthHandler) SetupRoutes() *mux.Router {
	r := mux.NewRouter()

	// public routes
	r.HandleFunc("/api/auth/register", h.Register).Methods("POST")
	r.HandleFunc("/api/auth/login", h.Login).Methods("POST")
	r.HandleFunc("/api/auth/refresh", h.RefreshToken).Methods("POST")
	r.HandleFunc("/api/auth/password-reset", h.RequestPasswordReset).Methods("POST")
	r.HandleFunc("/api/auth/password-reset/confirm", h.ResetPassword).Methods("POST")

	// protected routes
	protected := r.PathPrefix("/api").Subrouter()
	protected.Use(middleware.AuthMiddleware)
	protected.HandleFunc("/me", h.GetMe).Methods("GET")

	// health check
	r.HandleFunc("/health", h.Health).Methods("GET")

	return r
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req domain.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	resp, err := h.authService.Register(r.Context(), &req)
	if err != nil {
		if err == domain.ErrUserAlreadyExists {
			respondWithError(w, http.StatusConflict, err.Error())
			return
		}
		// log error
		log.Printf("Failed to register user: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Failed to register user")
		return
	}

	respondWithJSON(w, http.StatusCreated, resp)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req domain.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	resp, err := h.authService.Login(r.Context(), &req)
	if err != nil {
		if err == domain.ErrInvalidCredentials {
			respondWithError(w, http.StatusUnauthorized, err.Error())
			return
		}
		respondWithError(w, http.StatusInternalServerError, "Failed to login")
		return
	}

	respondWithJSON(w, http.StatusOK, resp)
}

func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req domain.RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	resp, err := h.authService.RefreshToken(r.Context(), &req)
	if err != nil {
		if err == domain.ErrInvalidCredentials {
			respondWithError(w, http.StatusUnauthorized, err.Error())
			return
		}
		respondWithError(w, http.StatusInternalServerError, "Failed to refresh token")
		return
	}

	respondWithJSON(w, http.StatusOK, resp)
}

func (h *AuthHandler) GetMe(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(middleware.UserIDKey).(uuid.UUID)

	user, err := h.authService.GetUserByID(r.Context(), userID)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "User not found")
		return
	}

	respondWithJSON(w, http.StatusOK, user)
}

func (h *AuthHandler) Health(w http.ResponseWriter, r *http.Request) {
	respondWithJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *AuthHandler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req domain.PasswordResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	resp, err := h.authService.RequestPasswordReset(r.Context(), &req)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to process password reset request")
		return
	}

	respondWithJSON(w, http.StatusOK, resp)
}

func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req domain.PasswordResetConfirmRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	resp, err := h.authService.ResetPassword(r.Context(), &req)
	if err != nil {
		if err == domain.ErrInvalidResetToken || err == domain.ErrResetTokenExpired {
			respondWithError(w, http.StatusBadRequest, err.Error())
			return
		}
		respondWithError(w, http.StatusInternalServerError, "Failed to reset password")
		return
	}

	respondWithJSON(w, http.StatusOK, resp)
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, map[string]string{"error": message})
}
