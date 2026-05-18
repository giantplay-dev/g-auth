package password

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateDefault_ValidPassword(t *testing.T) {
	err := ValidateDefault("Secure@123")
	assert.NoError(t, err)
}

func TestValidateDefault_TooShort(t *testing.T) {
	err := ValidateDefault("Ab1@")
	require.Error(t, err)
	weakErr, ok := err.(ErrWeakPassword)
	require.True(t, ok)
	assert.Len(t, weakErr.Violations, 1)
	assert.Contains(t, weakErr.Violations[0], "at least 8 characters")
}

func TestValidateDefault_NoUppercase(t *testing.T) {
	err := ValidateDefault("secure@123")
	require.Error(t, err)
	weakErr, ok := err.(ErrWeakPassword)
	require.True(t, ok)
	assert.True(t, containsViolation(weakErr.Violations, "uppercase"))
}

func TestValidateDefault_NoLowercase(t *testing.T) {
	err := ValidateDefault("SECURE@123")
	require.Error(t, err)
	weakErr, ok := err.(ErrWeakPassword)
	require.True(t, ok)
	assert.True(t, containsViolation(weakErr.Violations, "lowercase"))
}

func TestValidateDefault_NoDigit(t *testing.T) {
	err := ValidateDefault("Secure@abc")
	require.Error(t, err)
	weakErr, ok := err.(ErrWeakPassword)
	require.True(t, ok)
	assert.True(t, containsViolation(weakErr.Violations, "digit"))
}

func TestValidateDefault_NoSpecialCharacter(t *testing.T) {
	err := ValidateDefault("Secure123")
	require.Error(t, err)
	weakErr, ok := err.(ErrWeakPassword)
	require.True(t, ok)
	assert.True(t, containsViolation(weakErr.Violations, "special character"))
}

func TestValidateDefault_MultipleViolations(t *testing.T) {
	// all lowercase, no digit, no special char
	err := ValidateDefault("alllowercase")
	require.Error(t, err)
	weakErr, ok := err.(ErrWeakPassword)
	require.True(t, ok)
	assert.True(t, len(weakErr.Violations) > 1)
}

func TestValidateDefault_EmptyPassword(t *testing.T) {
	err := ValidateDefault("")
	require.Error(t, err)
	_, ok := err.(ErrWeakPassword)
	assert.True(t, ok)
}

func TestErrWeakPassword_Error_SingleViolation(t *testing.T) {
	err := ErrWeakPassword{Violations: []string{"must be at least 8 characters long"}}
	assert.Contains(t, err.Error(), "must be at least 8 characters long")
}

func TestErrWeakPassword_Error_MultipleViolations(t *testing.T) {
	err := ErrWeakPassword{Violations: []string{"must contain at least one digit", "must contain at least one uppercase letter"}}
	msg := err.Error()
	assert.Contains(t, msg, "digit")
	assert.Contains(t, msg, "uppercase")
}

func TestPolicy_CustomPolicy(t *testing.T) {
	p := Policy{MinLength: 4, RequireUppercase: false, RequireLowercase: false, RequireDigit: false, RequireSpecial: false}
	assert.NoError(t, p.Validate("abcd"))
	assert.Error(t, p.Validate("abc"))
}

// containsViolation checks whether any violation message contains the given substring.
func containsViolation(violations []string, substr string) bool {
	for _, v := range violations {
		if strings.Contains(v, substr) {
			return true
		}
	}
	return false
}
