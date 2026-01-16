# Mailer Package

## Overview

The `pkg/mailer` package provides email sending functionality for the authentication service. It supports SMTP email delivery and includes a no-operation mailer for testing and development environments.

## Features

- **SMTP Support**: Send emails via SMTP servers (Gmail, SendGrid, etc.)
- **HTML Emails**: Support for HTML email content
- **No-Op Mailer**: Safe mailer for testing that doesn't send actual emails
- **Interface-Based Design**: Easy to mock and test

## Configuration

Add the following environment variables to configure SMTP:

```bash
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=noreply@yourapp.com
```

## Usage

### SMTP Mailer

```go
import "g-auth/pkg/mailer"

mailer := mailer.NewSMTPMailer("smtp.gmail.com", 587, "user@gmail.com", "password", "noreply@yourapp.com")
err := mailer.SendEmail("recipient@example.com", "Subject", "<h1>HTML Content</h1>")
```

### No-Op Mailer (for testing)

```go
import "g-auth/pkg/mailer"

mailer := mailer.NewNoOpMailer()
// This will not send any emails
err := mailer.SendEmail("test@example.com", "Test", "Content")
```

## Email Templates

The service includes a built-in HTML template for password reset emails. The template includes:

- Professional styling
- Clear call-to-action button
- Security warnings
- Responsive design

## Security Considerations

- Never log email content or passwords
- Use app-specific passwords for Gmail
- Configure SPF/DKIM records for your domain
- Use HTTPS for email links
- Implement rate limiting for email sending

## Error Handling

Email sending errors are logged but don't fail the user request (especially for password reset to avoid revealing email existence). In production, consider:

- Retry mechanisms
- Dead letter queues
- Alerting for delivery failures
- Fallback to alternative delivery methods

---

**Last Updated**: January 11, 2026