package password

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHash(t *testing.T) {
	password := "testPassword123"

	hashedPassword, err := Hash(password)

	assert.NoError(t, err)
	assert.NotEmpty(t, hashedPassword)
	assert.NotEqual(t, password, hashedPassword)
}

func TestHash_DifferentPasswords(t *testing.T) {
	password1 := "password1"
	password2 := "password2"

	hash1, err := Hash(password1)
	assert.NoError(t, err)

	hash2, err := Hash(password2)
	assert.NoError(t, err)

	assert.NotEqual(t, hash1, hash2)
}

func TestHash_SamePasswordDifferentHashes(t *testing.T) {
	password := "samePassword"

	hash1, err := Hash(password)
	assert.NoError(t, err)

	hash2, err := Hash(password)
	assert.NoError(t, err)

	// bcrypt generates different hashes for the same password (due to salt)
	assert.NotEqual(t, hash1, hash2)
}

func TestVerify_Success(t *testing.T) {
	password := "correctPassword123"

	hashedPassword, err := Hash(password)
	assert.NoError(t, err)

	result := Verify(password, hashedPassword)

	assert.True(t, result)
}

func TestVerify_WrongPassword(t *testing.T) {
	password := "correctPassword123"
	wrongPassword := "wrongPassword456"

	hashedPassword, err := Hash(password)
	assert.NoError(t, err)

	result := Verify(wrongPassword, hashedPassword)

	assert.False(t, result)
}

func TestVerify_InvalidHash(t *testing.T) {
	password := "testPassword"
	invalidHash := "not-a-valid-bcrypt-hash"

	result := Verify(password, invalidHash)

	assert.False(t, result)
}

func TestVerify_EmptyPassword(t *testing.T) {
	emptyPassword := ""

	hashedPassword, err := Hash(emptyPassword)
	assert.NoError(t, err)

	result := Verify(emptyPassword, hashedPassword)

	assert.True(t, result)
}

func TestVerify_EmptyPasswordAgainstNonEmptyHash(t *testing.T) {
	password := "nonEmptyPassword"
	emptyPassword := ""

	hashedPassword, err := Hash(password)
	assert.NoError(t, err)

	result := Verify(emptyPassword, hashedPassword)

	assert.False(t, result)
}
