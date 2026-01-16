package middleware

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"g-auth/pkg/jwt"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestAuthMiddleware_MissingAuthorizationHeader(t *testing.T) {
	handler := AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Authorization header required")
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	// Set up environment for config
	os.Setenv("JWT_SECRET", "test-secret")
	defer os.Unsetenv("JWT_SECRET")

	handler := AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid token")
}

func TestAuthMiddleware_TokenWithoutBearerPrefix(t *testing.T) {
	// Set up environment for config
	os.Setenv("JWT_SECRET", "test-secret")
	defer os.Unsetenv("JWT_SECRET")

	handler := AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "invalid-format-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestUserIDKey_Constant(t *testing.T) {
	assert.Equal(t, contextKey("userID"), UserIDKey)
}

func TestAuthMiddleware_ValidToken(t *testing.T) {
	// Set up environment for config
	os.Setenv("JWT_SECRET", "test-secret-key")
	os.Setenv("JWT_EXPIRATION", "1h")
	os.Setenv("REFRESH_TOKEN_EXPIRATION", "24h")
	defer func() {
		os.Unsetenv("JWT_SECRET")
		os.Unsetenv("JWT_EXPIRATION")
		os.Unsetenv("REFRESH_TOKEN_EXPIRATION")
	}()

	// Generate a valid token
	jwtManager := jwt.NewJWTManager("test-secret-key", time.Hour, 24*time.Hour)
	userID := uuid.New()
	token, err := jwtManager.Generate(userID, "test@example.com")
	assert.NoError(t, err)

	var capturedUserID uuid.UUID
	handler := AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify that userID was added to context
		capturedUserID = r.Context().Value(UserIDKey).(uuid.UUID)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, userID, capturedUserID)
}
