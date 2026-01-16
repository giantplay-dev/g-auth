package mailer

import (
	"fmt"

	"gopkg.in/gomail.v2"
)

// Mailer defines the interface for sending emails
type Mailer interface {
	SendEmail(to, subject, body string) error
}

// SMTPMailer implements the Mailer interface using SMTP
type SMTPMailer struct {
	dialer *gomail.Dialer
	from   string
}

// NewSMTPMailer creates a new SMTP mailer instance
func NewSMTPMailer(host string, port int, username, password, from string) Mailer {
	dialer := gomail.NewDialer(host, port, username, password)
	return &SMTPMailer{
		dialer: dialer,
		from:   from,
	}
}

// SendEmail sends an email using SMTP
func (m *SMTPMailer) SendEmail(to, subject, body string) error {
	msg := gomail.NewMessage()
	msg.SetHeader("From", m.from)
	msg.SetHeader("To", to)
	msg.SetHeader("Subject", subject)
	msg.SetBody("text/html", body)

	if err := m.dialer.DialAndSend(msg); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

// NoOpMailer is a no-operation mailer for testing or when email is disabled
type NoOpMailer struct{}

// NewNoOpMailer creates a new no-operation mailer
func NewNoOpMailer() Mailer {
	return &NoOpMailer{}
}

// SendEmail does nothing and returns nil
func (m *NoOpMailer) SendEmail(to, subject, body string) error {
	// In a real implementation, you might log the email instead
	return nil
}
