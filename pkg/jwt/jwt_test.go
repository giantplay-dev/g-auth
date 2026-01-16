package jwt

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewJWTManager(t *testing.T) {
	manager := NewJWTManager("test-secret", time.Hour, 24*time.Hour)

	assert.NotNil(t, manager)
	assert.Equal(t, "test-secret", manager.secretKey)
	assert.Equal(t, time.Hour, manager.expiration)
	assert.Equal(t, 24*time.Hour, manager.refreshExpiration)
}

func TestJWTManager_Generate(t *testing.T) {
	manager := NewJWTManager("test-secret", time.Hour, 24*time.Hour)
	userID := uuid.New()
	email := "test@example.com"

	token, err := manager.Generate(userID, email)

	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestJWTManager_Verify_Success(t *testing.T) {
	manager := NewJWTManager("test-secret", time.Hour, 24*time.Hour)
	userID := uuid.New()
	email := "test@example.com"

	token, err := manager.Generate(userID, email)
	assert.NoError(t, err)

	claims, err := manager.Verify(token)

	assert.NoError(t, err)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, email, claims.Email)
	assert.Empty(t, claims.Roles)
}

func TestJWTManager_GenerateWithRoles(t *testing.T) {
	manager := NewJWTManager("test-secret", time.Hour, 24*time.Hour)
	userID := uuid.New()
	email := "test@example.com"
	roles := []string{"admin", "user"}

	token, err := manager.GenerateWithRoles(userID, email, roles)
	assert.NoError(t, err)

	claims, err := manager.Verify(token)
	assert.NoError(t, err)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, email, claims.Email)
	assert.Equal(t, roles, claims.Roles)
}

func TestJWTManager_Verify_InvalidToken(t *testing.T) {
	manager := NewJWTManager("test-secret", time.Hour, 24*time.Hour)

	claims, err := manager.Verify("invalid-token")

	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestJWTManager_Verify_WrongSecret(t *testing.T) {
	manager1 := NewJWTManager("secret-1", time.Hour, 24*time.Hour)
	manager2 := NewJWTManager("secret-2", time.Hour, 24*time.Hour)
	userID := uuid.New()
	email := "test@example.com"

	token, err := manager1.Generate(userID, email)
	assert.NoError(t, err)

	claims, err := manager2.Verify(token)

	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestJWTManager_Verify_ExpiredToken(t *testing.T) {
	// Create manager with very short expiration
	manager := NewJWTManager("test-secret", -time.Hour, 24*time.Hour)
	userID := uuid.New()
	email := "test@example.com"

	token, err := manager.Generate(userID, email)
	assert.NoError(t, err)

	claims, err := manager.Verify(token)

	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestJWTManager_GenerateRefreshToken(t *testing.T) {
	manager := NewJWTManager("test-secret", time.Hour, 24*time.Hour)
	userID := uuid.New()

	refreshToken, err := manager.GenerateRefreshToken(userID)

	assert.NoError(t, err)
	assert.NotEmpty(t, refreshToken)
}

func TestJWTManager_VerifyRefreshToken_Success(t *testing.T) {
	manager := NewJWTManager("test-secret", time.Hour, 24*time.Hour)
	userID := uuid.New()

	refreshToken, err := manager.GenerateRefreshToken(userID)
	assert.NoError(t, err)

	claims, err := manager.VerifyRefreshToken(refreshToken)

	assert.NoError(t, err)
	assert.Equal(t, userID, claims.UserID)
}

func TestJWTManager_VerifyRefreshToken_InvalidToken(t *testing.T) {
	manager := NewJWTManager("test-secret", time.Hour, 24*time.Hour)

	claims, err := manager.VerifyRefreshToken("invalid-refresh-token")

	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestJWTManager_VerifyRefreshToken_WrongSecret(t *testing.T) {
	manager1 := NewJWTManager("secret-1", time.Hour, 24*time.Hour)
	manager2 := NewJWTManager("secret-2", time.Hour, 24*time.Hour)
	userID := uuid.New()

	refreshToken, err := manager1.GenerateRefreshToken(userID)
	assert.NoError(t, err)

	claims, err := manager2.VerifyRefreshToken(refreshToken)

	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestJWTManager_VerifyRefreshToken_ExpiredToken(t *testing.T) {
	// Create manager with very short refresh expiration
	manager := NewJWTManager("test-secret", time.Hour, -time.Hour)
	userID := uuid.New()

	refreshToken, err := manager.GenerateRefreshToken(userID)
	assert.NoError(t, err)

	claims, err := manager.VerifyRefreshToken(refreshToken)

	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestJWTManager_Verify_InvalidSigningMethod(t *testing.T) {
	manager := NewJWTManager("test-secret", time.Hour, 24*time.Hour)

	// Create a token with none algorithm (malicious token attempt)
	invalidToken := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoiMTIzIiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIn0."

	claims, err := manager.Verify(invalidToken)

	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestJWTManager_VerifyRefreshToken_InvalidSigningMethod(t *testing.T) {
	manager := NewJWTManager("test-secret", time.Hour, 24*time.Hour)

	// Create a token with none algorithm (malicious token attempt)
	invalidToken := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoiMTIzIn0."

	claims, err := manager.VerifyRefreshToken(invalidToken)

	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestJWTManager_Verify_MalformedToken(t *testing.T) {
	manager := NewJWTManager("test-secret", time.Hour, 24*time.Hour)

	// Test with completely malformed tokens
	malformedTokens := []string{
		"",
		"not.a.token",
		"aaa.bbb.ccc",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", // only header
	}

	for _, token := range malformedTokens {
		claims, err := manager.Verify(token)
		assert.Error(t, err)
		assert.Nil(t, claims)
	}
}

func TestJWTManager_VerifyRefreshToken_MalformedToken(t *testing.T) {
	manager := NewJWTManager("test-secret", time.Hour, 24*time.Hour)

	// Test with completely malformed tokens
	malformedTokens := []string{
		"",
		"not.a.token",
		"aaa.bbb.ccc",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", // only header
	}

	for _, token := range malformedTokens {
		claims, err := manager.VerifyRefreshToken(token)
		assert.Error(t, err)
		assert.Nil(t, claims)
	}
}
