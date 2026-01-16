package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLoad_DefaultValues(t *testing.T) {
	// Clear environment variables to test defaults
	os.Unsetenv("APP_ENV")
	os.Unsetenv("APP_PORT")
	os.Unsetenv("DATABASE_URL")
	os.Unsetenv("JWT_SECRET")
	os.Unsetenv("SMTP_HOST")
	os.Unsetenv("SMTP_PORT")
	os.Unsetenv("SMTP_USERNAME")
	os.Unsetenv("SMTP_PASSWORD")
	os.Unsetenv("SMTP_FROM")
	os.Unsetenv("RATE_LIMIT")
	os.Unsetenv("RATE_LIMIT_BURST")

	cfg := Load()

	assert.Equal(t, "development", cfg.Env)
	assert.Equal(t, "8080", cfg.Port)
	assert.Equal(t, "postgres://user:pass@localhost:5432/dbname", cfg.DatabaseURL)
	assert.Equal(t, "supersecretkey", cfg.JWTSecret)
	assert.Equal(t, 15*time.Minute, cfg.JWTExpiration)
	assert.Equal(t, 7*24*time.Hour, cfg.RefreshTokenExpiration)
	assert.Equal(t, "smtp.gmail.com", cfg.SMTPHost)
	assert.Equal(t, "587", cfg.SMTPPort)
	assert.Equal(t, "", cfg.SMTPUsername)
	assert.Equal(t, "", cfg.SMTPPassword)
	assert.Equal(t, "", cfg.SMTPFrom)
	assert.Equal(t, 10, cfg.RateLimit)
	assert.Equal(t, 20, cfg.RateLimitBurst)
}

func TestLoad_WithEnvironmentVariables(t *testing.T) {
	// Set environment variables
	os.Setenv("APP_ENV", "production")
	os.Setenv("APP_PORT", "3000")
	os.Setenv("DATABASE_URL", "postgres://prod:password@db.example.com:5432/proddb")
	os.Setenv("JWT_SECRET", "production-secret")
	os.Setenv("SMTP_HOST", "smtp.production.com")
	os.Setenv("SMTP_PORT", "465")
	os.Setenv("SMTP_USERNAME", "smtp_user")
	os.Setenv("SMTP_PASSWORD", "smtp_pass")
	os.Setenv("SMTP_FROM", "noreply@example.com")
	os.Setenv("RATE_LIMIT", "100")
	os.Setenv("RATE_LIMIT_BURST", "200")

	defer func() {
		// Clean up environment variables
		os.Unsetenv("APP_ENV")
		os.Unsetenv("APP_PORT")
		os.Unsetenv("DATABASE_URL")
		os.Unsetenv("JWT_SECRET")
		os.Unsetenv("SMTP_HOST")
		os.Unsetenv("SMTP_PORT")
		os.Unsetenv("SMTP_USERNAME")
		os.Unsetenv("SMTP_PASSWORD")
		os.Unsetenv("SMTP_FROM")
		os.Unsetenv("RATE_LIMIT")
		os.Unsetenv("RATE_LIMIT_BURST")
	}()

	cfg := Load()

	assert.Equal(t, "production", cfg.Env)
	assert.Equal(t, "3000", cfg.Port)
	assert.Equal(t, "postgres://prod:password@db.example.com:5432/proddb", cfg.DatabaseURL)
	assert.Equal(t, "production-secret", cfg.JWTSecret)
	assert.Equal(t, "smtp.production.com", cfg.SMTPHost)
	assert.Equal(t, "465", cfg.SMTPPort)
	assert.Equal(t, "smtp_user", cfg.SMTPUsername)
	assert.Equal(t, "smtp_pass", cfg.SMTPPassword)
	assert.Equal(t, "noreply@example.com", cfg.SMTPFrom)
	assert.Equal(t, 100, cfg.RateLimit)
	assert.Equal(t, 200, cfg.RateLimitBurst)
}

func TestGetEnv_WithValue(t *testing.T) {
	os.Setenv("TEST_KEY", "test_value")
	defer os.Unsetenv("TEST_KEY")

	result := getEnv("TEST_KEY", "default_value")

	assert.Equal(t, "test_value", result)
}

func TestGetEnv_WithDefaultValue(t *testing.T) {
	os.Unsetenv("NONEXISTENT_KEY")

	result := getEnv("NONEXISTENT_KEY", "default_value")

	assert.Equal(t, "default_value", result)
}

func TestGetEnvAsInt_WithValidValue(t *testing.T) {
	os.Setenv("TEST_INT", "42")
	defer os.Unsetenv("TEST_INT")

	result := getEnvAsInt("TEST_INT", 10)

	assert.Equal(t, 42, result)
}

func TestGetEnvAsInt_WithInvalidValue(t *testing.T) {
	os.Setenv("TEST_INT", "not_a_number")
	defer os.Unsetenv("TEST_INT")

	result := getEnvAsInt("TEST_INT", 10)

	assert.Equal(t, 10, result)
}

func TestGetEnvAsInt_WithEmptyValue(t *testing.T) {
	os.Unsetenv("NONEXISTENT_INT")

	result := getEnvAsInt("NONEXISTENT_INT", 10)

	assert.Equal(t, 10, result)
}

func TestGetEnvAsInt_WithNegativeValue(t *testing.T) {
	os.Setenv("TEST_INT", "-5")
	defer os.Unsetenv("TEST_INT")

	result := getEnvAsInt("TEST_INT", 10)

	assert.Equal(t, -5, result)
}

func TestGetEnvAsInt_WithZeroValue(t *testing.T) {
	os.Setenv("TEST_INT", "0")
	defer os.Unsetenv("TEST_INT")

	result := getEnvAsInt("TEST_INT", 10)

	assert.Equal(t, 0, result)
}
