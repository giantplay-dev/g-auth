package mfa

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"
)

const (
	// CodeLength defines the length of the MFA code
	CodeLength = 6
	// CodeValidityDuration defines how long a code is valid
	CodeValidityDuration = 10 * time.Minute
)

// GenerateCode generates a random 6-digit MFA code
func GenerateCode() (string, error) {
	// Generate a random 6-digit number between 000000 and 999999
	max := big.NewInt(1000000)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", fmt.Errorf("failed to generate MFA code: %w", err)
	}

	// Format as 6-digit string with leading zeros if necessary
	code := fmt.Sprintf("%06d", n.Int64())
	return code, nil
}

// GetExpirationTime returns the expiration time for a newly generated code
func GetExpirationTime() time.Time {
	return time.Now().Add(CodeValidityDuration)
}

// IsCodeValid checks if a code matches and is not expired
func IsCodeValid(providedCode, storedCode string, expiresAt *time.Time) bool {
	if providedCode == "" || storedCode == "" {
		return false
	}

	if providedCode != storedCode {
		return false
	}

	if expiresAt == nil {
		return false
	}

	if time.Now().After(*expiresAt) {
		return false
	}

	return true
}
