package password

import (
	"errors"
	"fmt"
	"unicode"
)

// Policy defines the requirements for a valid password.
type Policy struct {
	MinLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireDigit     bool
	RequireSpecial   bool
}

// DefaultPolicy is the application-wide password policy.
var DefaultPolicy = Policy{
	MinLength:        8,
	RequireUppercase: true,
	RequireLowercase: true,
	RequireDigit:     true,
	RequireSpecial:   true,
}

// ErrWeakPassword is returned when a password does not satisfy the policy.
type ErrWeakPassword struct {
	Violations []string
}

func (e ErrWeakPassword) Error() string {
	if len(e.Violations) == 1 {
		return fmt.Sprintf("password policy violation: %s", e.Violations[0])
	}
	msg := "password policy violations:"
	for _, v := range e.Violations {
		msg += " " + v + ";"
	}
	return msg
}

func (e ErrWeakPassword) Unwrap() error {
	return errors.New(e.Error())
}

// Validate checks the given password against the policy and returns an
// ErrWeakPassword if any requirements are not met.
func (p Policy) Validate(pw string) error {
	var violations []string

	if len(pw) < p.MinLength {
		violations = append(violations, fmt.Sprintf("must be at least %d characters long", p.MinLength))
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, ch := range pw {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasDigit = true
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			hasSpecial = true
		}
	}

	if p.RequireUppercase && !hasUpper {
		violations = append(violations, "must contain at least one uppercase letter")
	}
	if p.RequireLowercase && !hasLower {
		violations = append(violations, "must contain at least one lowercase letter")
	}
	if p.RequireDigit && !hasDigit {
		violations = append(violations, "must contain at least one digit")
	}
	if p.RequireSpecial && !hasSpecial {
		violations = append(violations, "must contain at least one special character")
	}

	if len(violations) > 0 {
		return ErrWeakPassword{Violations: violations}
	}
	return nil
}

// ValidateDefault validates the given password against the DefaultPolicy.
func ValidateDefault(pw string) error {
	return DefaultPolicy.Validate(pw)
}
