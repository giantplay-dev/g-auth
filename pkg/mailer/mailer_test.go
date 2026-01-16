package mailer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNoOpMailer_SendEmail(t *testing.T) {
	mailer := NewNoOpMailer()

	err := mailer.SendEmail("test@example.com", "Test Subject", "Test Body")

	assert.NoError(t, err)
}

func TestSMTPMailer_NewSMTPMailer(t *testing.T) {
	mailer := NewSMTPMailer("smtp.example.com", 587, "user", "pass", "from@example.com")

	assert.NotNil(t, mailer)
	assert.IsType(t, &SMTPMailer{}, mailer)
}

// Note: Integration test for actual email sending would require real SMTP server
// and should be run separately with proper environment setup
