package mfa

import (
	"testing"
	"time"
)

func TestGenerateCode(t *testing.T) {
	code, err := GenerateCode()
	if err != nil {
		t.Fatalf("GenerateCode() error = %v", err)
	}

	if len(code) != CodeLength {
		t.Errorf("GenerateCode() code length = %d, want %d", len(code), CodeLength)
	}

	// Verify code is numeric
	for _, c := range code {
		if c < '0' || c > '9' {
			t.Errorf("GenerateCode() contains non-numeric character: %c", c)
		}
	}
}

func TestGenerateCodeUniqueness(t *testing.T) {
	codes := make(map[string]bool)
	iterations := 100

	for i := 0; i < iterations; i++ {
		code, err := GenerateCode()
		if err != nil {
			t.Fatalf("GenerateCode() error = %v", err)
		}
		codes[code] = true
	}

	// We should have mostly unique codes (allow some duplicates due to randomness)
	// With 6 digits (1,000,000 possibilities) and 100 iterations, duplicates are rare but possible
	if len(codes) < iterations/2 {
		t.Errorf("GenerateCode() produced too many duplicates: %d unique out of %d", len(codes), iterations)
	}
}

func TestGetExpirationTime(t *testing.T) {
	before := time.Now()
	expiresAt := GetExpirationTime()
	after := time.Now()

	expectedMin := before.Add(CodeValidityDuration)
	expectedMax := after.Add(CodeValidityDuration)

	if expiresAt.Before(expectedMin) || expiresAt.After(expectedMax) {
		t.Errorf("GetExpirationTime() = %v, want between %v and %v", expiresAt, expectedMin, expectedMax)
	}
}

func TestIsCodeValid(t *testing.T) {
	validCode := "123456"
	futureExpiration := time.Now().Add(5 * time.Minute)
	pastExpiration := time.Now().Add(-5 * time.Minute)

	tests := []struct {
		name         string
		providedCode string
		storedCode   string
		expiresAt    *time.Time
		want         bool
	}{
		{
			name:         "valid code and not expired",
			providedCode: validCode,
			storedCode:   validCode,
			expiresAt:    &futureExpiration,
			want:         true,
		},
		{
			name:         "invalid code",
			providedCode: "654321",
			storedCode:   validCode,
			expiresAt:    &futureExpiration,
			want:         false,
		},
		{
			name:         "expired code",
			providedCode: validCode,
			storedCode:   validCode,
			expiresAt:    &pastExpiration,
			want:         false,
		},
		{
			name:         "empty provided code",
			providedCode: "",
			storedCode:   validCode,
			expiresAt:    &futureExpiration,
			want:         false,
		},
		{
			name:         "empty stored code",
			providedCode: validCode,
			storedCode:   "",
			expiresAt:    &futureExpiration,
			want:         false,
		},
		{
			name:         "nil expiration",
			providedCode: validCode,
			storedCode:   validCode,
			expiresAt:    nil,
			want:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsCodeValid(tt.providedCode, tt.storedCode, tt.expiresAt)
			if got != tt.want {
				t.Errorf("IsCodeValid() = %v, want %v", got, tt.want)
			}
		})
	}
}
