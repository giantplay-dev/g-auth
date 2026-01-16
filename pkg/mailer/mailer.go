package mailer

import (
	"fmt"

	"gopkg.in/gomail.v2"
)

// Mailer defines the interface for sending emails
type Mailer interface {
	SendEmail(to, subject, body string) error
	SendMFACode(to, name, code string) error
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

// SendMFACode sends an MFA code email to the user
func (m *SMTPMailer) SendMFACode(to, name, code string) error {
	subject := "Your Multi-Factor Authentication Code"
	body := buildMFACodeEmail(name, code)
	return m.SendEmail(to, subject, body)
}

func buildMFACodeEmail(name, code string) string {
	return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>MFA Code</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #4CAF50;">Multi-Factor Authentication</h2>
        
        <p>Hello ` + name + `,</p>
        
        <p>Your multi-factor authentication code is:</p>
        
        <div style="text-align: center; margin: 30px 0;">
            <div style="display: inline-block; background-color: #f5f5f5; padding: 20px 40px; border-radius: 8px; font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #333;">
                ` + code + `
            </div>
        </div>
        
        <p><strong>Important:</strong> This code will expire in 10 minutes for security reasons.</p>
        
        <p>If you didn't request this code, please ignore this email and ensure your account is secure.</p>
        
        <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
        
        <p style="color: #666; font-size: 12px;">
            This is an automated email. Please do not reply to this message.
        </p>
    </div>
</body>
</html>
`
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

// SendMFACode does nothing and returns nil
func (m *NoOpMailer) SendMFACode(to, name, code string) error {
	// In a real implementation, you might log the MFA code instead
	return nil
}
