package e2e_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"g-auth/internal/domain"
)

// ----- helpers -----

func post(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	require.NoError(t, err)
	return resp
}

func getWithToken(t *testing.T, url, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

func decodeJSON(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	require.NoError(t, json.NewDecoder(resp.Body).Decode(v))
}

// registerAndVerify registers a user, retrieves the verification token from the
// in-memory repo, calls the verify-email endpoint, then returns the email and password.
func registerAndVerify(t *testing.T, env *testEnv, email, password, name string) {
	t.Helper()
	baseURL := env.server.URL

	// Register
	resp := post(t, baseURL+"/api/auth/register", domain.RegisterRequest{
		Email:    email,
		Password: password,
		Name:     name,
	})
	resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Grab verification token from in-memory store
	user := env.userRepo.GetUserByEmail(email)
	require.NotNil(t, user)
	require.NotNil(t, user.VerificationToken)

	// Verify email
	resp = post(t, baseURL+"/api/auth/verify-email", domain.EmailVerificationRequest{
		Token: *user.VerificationToken,
	})
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

// login performs a login and returns the AuthResponse.
func login(t *testing.T, env *testEnv, email, password string) domain.AuthResponse {
	t.Helper()
	resp := post(t, env.server.URL+"/api/auth/login", domain.LoginRequest{
		Email:    email,
		Password: password,
	})
	var auth domain.AuthResponse
	decodeJSON(t, resp, &auth)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return auth
}

// ----- Tests -----

func TestE2E_HealthCheck(t *testing.T) {
	env := newTestEnv(t)

	resp, err := http.Get(env.server.URL + "/health")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]string
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "ok", body["status"])
}

func TestE2E_Register_Success(t *testing.T) {
	env := newTestEnv(t)

	resp := post(t, env.server.URL+"/api/auth/register", domain.RegisterRequest{
		Email:    "alice@example.com",
		Password: "Secure@123",
		Name:     "Alice",
	})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var body domain.RegisterResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.NotEmpty(t, body.Message)
}

func TestE2E_Register_DuplicateEmail(t *testing.T) {
	env := newTestEnv(t)

	payload := domain.RegisterRequest{
		Email:    "dup@example.com",
		Password: "Secure@123",
		Name:     "Dup",
	}

	resp := post(t, env.server.URL+"/api/auth/register", payload)
	resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	resp2 := post(t, env.server.URL+"/api/auth/register", payload)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusConflict, resp2.StatusCode)
}

func TestE2E_Register_WeakPassword_TooShort(t *testing.T) {
	env := newTestEnv(t)

	resp := post(t, env.server.URL+"/api/auth/register", domain.RegisterRequest{
		Email:    "weak@example.com",
		Password: "Ab1@",
		Name:     "Weak",
	})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestE2E_Register_WeakPassword_NoSpecialChar(t *testing.T) {
	env := newTestEnv(t)

	resp := post(t, env.server.URL+"/api/auth/register", domain.RegisterRequest{
		Email:    "weak2@example.com",
		Password: "Secure123",
		Name:     "Weak2",
	})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestE2E_Register_WeakPassword_NoUppercase(t *testing.T) {
	env := newTestEnv(t)

	resp := post(t, env.server.URL+"/api/auth/register", domain.RegisterRequest{
		Email:    "weak3@example.com",
		Password: "secure@123",
		Name:     "Weak3",
	})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestE2E_FullAuthFlow_RegisterVerifyLogin(t *testing.T) {
	env := newTestEnv(t)
	email := "bob@example.com"
	password := "Secure@123"

	registerAndVerify(t, env, email, password, "Bob")

	auth := login(t, env, email, password)

	assert.NotEmpty(t, auth.Token)
	assert.NotEmpty(t, auth.RefreshToken)
	assert.Equal(t, email, auth.User.Email)
}

func TestE2E_Login_EmailNotVerified(t *testing.T) {
	env := newTestEnv(t)

	// Register only, do not verify
	resp := post(t, env.server.URL+"/api/auth/register", domain.RegisterRequest{
		Email:    "unverified@example.com",
		Password: "Secure@123",
		Name:     "Unverified",
	})
	resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	resp2 := post(t, env.server.URL+"/api/auth/login", domain.LoginRequest{
		Email:    "unverified@example.com",
		Password: "Secure@123",
	})
	defer resp2.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp2.StatusCode)
}

func TestE2E_Login_WrongPassword(t *testing.T) {
	env := newTestEnv(t)
	registerAndVerify(t, env, "carol@example.com", "Secure@123", "Carol")

	resp := post(t, env.server.URL+"/api/auth/login", domain.LoginRequest{
		Email:    "carol@example.com",
		Password: "WrongPass@999",
	})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestE2E_Login_NonExistentUser(t *testing.T) {
	env := newTestEnv(t)

	resp := post(t, env.server.URL+"/api/auth/login", domain.LoginRequest{
		Email:    "nobody@example.com",
		Password: "Secure@123",
	})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestE2E_ProtectedRoute_NoToken(t *testing.T) {
	env := newTestEnv(t)

	resp, err := http.Get(env.server.URL + "/api/me")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestE2E_ProtectedRoute_WithValidToken(t *testing.T) {
	env := newTestEnv(t)
	email := "dave@example.com"
	password := "Secure@123"

	registerAndVerify(t, env, email, password, "Dave")
	auth := login(t, env, email, password)

	resp := getWithToken(t, env.server.URL+"/api/me", auth.Token)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var user domain.User
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&user))
	assert.Equal(t, email, user.Email)
}

func TestE2E_ProtectedRoute_InvalidToken(t *testing.T) {
	env := newTestEnv(t)

	resp := getWithToken(t, env.server.URL+"/api/me", "this.is.not.a.valid.token")
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestE2E_RefreshToken(t *testing.T) {
	env := newTestEnv(t)
	email := "eve@example.com"
	password := "Secure@123"

	registerAndVerify(t, env, email, password, "Eve")
	auth := login(t, env, email, password)

	resp := post(t, env.server.URL+"/api/auth/refresh", domain.RefreshTokenRequest{
		RefreshToken: auth.RefreshToken,
	})
	var refreshed domain.AuthResponse
	decodeJSON(t, resp, &refreshed)

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotEmpty(t, refreshed.Token)
}

func TestE2E_RefreshToken_InvalidToken(t *testing.T) {
	env := newTestEnv(t)

	resp := post(t, env.server.URL+"/api/auth/refresh", domain.RefreshTokenRequest{
		RefreshToken: "invalid-refresh-token",
	})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestE2E_PasswordReset_FullFlow(t *testing.T) {
	env := newTestEnv(t)
	email := "frank@example.com"
	oldPassword := "Secure@123"
	newPassword := "NewSecure@456"

	registerAndVerify(t, env, email, oldPassword, "Frank")

	// Request password reset
	resp := post(t, env.server.URL+"/api/auth/password-reset", domain.PasswordResetRequest{
		Email: email,
	})
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Get reset token from in-memory store
	user := env.userRepo.GetUserByEmail(email)
	require.NotNil(t, user)
	require.NotNil(t, user.ResetToken)

	// Confirm password reset
	resp2 := post(t, env.server.URL+"/api/auth/password-reset/confirm", domain.PasswordResetConfirmRequest{
		Token:    *user.ResetToken,
		Password: newPassword,
	})
	resp2.Body.Close()
	require.Equal(t, http.StatusOK, resp2.StatusCode)

	// Login with new password
	auth := login(t, env, email, newPassword)
	assert.NotEmpty(t, auth.Token)

	// Old password should no longer work
	resp3 := post(t, env.server.URL+"/api/auth/login", domain.LoginRequest{
		Email:    email,
		Password: oldPassword,
	})
	defer resp3.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp3.StatusCode)
}

func TestE2E_PasswordReset_WeakNewPassword(t *testing.T) {
	env := newTestEnv(t)
	email := "grace@example.com"

	registerAndVerify(t, env, email, "Secure@123", "Grace")

	resp := post(t, env.server.URL+"/api/auth/password-reset", domain.PasswordResetRequest{
		Email: email,
	})
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	user := env.userRepo.GetUserByEmail(email)
	require.NotNil(t, user.ResetToken)

	resp2 := post(t, env.server.URL+"/api/auth/password-reset/confirm", domain.PasswordResetConfirmRequest{
		Token:    *user.ResetToken,
		Password: "weak",
	})
	defer resp2.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
}

func TestE2E_PasswordReset_InvalidToken(t *testing.T) {
	env := newTestEnv(t)

	resp := post(t, env.server.URL+"/api/auth/password-reset/confirm", domain.PasswordResetConfirmRequest{
		Token:    "nonexistent-reset-token",
		Password: "NewSecure@456",
	})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestE2E_AccountLockout(t *testing.T) {
	env := newTestEnv(t)
	email := "henry@example.com"

	registerAndVerify(t, env, email, "Secure@123", "Henry")

	// Exhaust all 5 attempts
	for i := 0; i < 5; i++ {
		resp := post(t, env.server.URL+"/api/auth/login", domain.LoginRequest{
			Email:    email,
			Password: "WrongPass@999",
		})
		resp.Body.Close()
	}

	// Account should now be locked → 429
	resp := post(t, env.server.URL+"/api/auth/login", domain.LoginRequest{
		Email:    email,
		Password: "Secure@123",
	})
	defer resp.Body.Close()

	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
}

func TestE2E_ResendVerification(t *testing.T) {
	env := newTestEnv(t)
	email := fmt.Sprintf("resend_%d@example.com", time.Now().UnixNano())

	resp := post(t, env.server.URL+"/api/auth/register", domain.RegisterRequest{
		Email:    email,
		Password: "Secure@123",
		Name:     "Resend",
	})
	resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	resp2 := post(t, env.server.URL+"/api/auth/resend-verification", domain.ResendVerificationRequest{
		Email: email,
	})
	defer resp2.Body.Close()

	assert.Equal(t, http.StatusOK, resp2.StatusCode)
}

func TestE2E_InvalidJSONPayload(t *testing.T) {
	env := newTestEnv(t)

	endpoints := []string{
		"/api/auth/register",
		"/api/auth/login",
		"/api/auth/refresh",
		"/api/auth/password-reset",
		"/api/auth/password-reset/confirm",
		"/api/auth/verify-email",
	}

	for _, ep := range endpoints {
		t.Run(ep, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, env.server.URL+ep, bytes.NewBufferString("{invalid json}"))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		})
	}
}
