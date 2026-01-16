# Password Reset

## Overview

The password reset feature allows users to reset their password through a two-step process: requesting a reset token via email and then confirming the reset with the new password. When a password reset is requested, an email containing a reset link is sent to the user's registered email address.

## Base Information

- **Base URL**: `http://localhost:8080`
- **API Version**: v1
- **Authentication**: None required
- **Content-Type**: `application/json`

## Endpoints

### 1. Request Password Reset

Request a password reset token to be sent to the user's email.

**Endpoint**: `POST /api/auth/password-reset`

**Request Headers**:
```
Content-Type: application/json
```

**Request Body**:
```json
{
  "email": "user@example.com"
}
```

**Request Fields**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| email | string | Yes | User's registered email address |

**Success Response** (200 OK):
```json
{
  "message": "If the email exists, a password reset link has been sent"
}
```

**Note**: For security reasons, the response is the same whether the email exists or not. If SMTP is not configured, the system will use a no-operation mailer and the reset link will not be sent (useful for development/testing).

**Error Responses**:

**400 Bad Request** - Invalid request format:
```json
{
  "error": "Invalid request payload"
}
```

**500 Internal Server Error** - Server error:
```json
{
  "error": "Failed to process password reset request"
}
```

**Example Request**:

```bash
curl -X POST http://localhost:8080/api/auth/password-reset \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com"
  }'
```

**Example Response**:
```json
{
  "message": "If the email exists, a password reset link has been sent"
}
```

### 2. Reset Password

Reset the user's password using a valid reset token.

**Endpoint**: `POST /api/auth/password-reset/confirm`

**Request Headers**:
```
Content-Type: application/json
```

**Request Body**:
```json
{
  "token": "reset-token-here",
  "password": "NewSecureP@ssw0rd"
}
```

**Request Fields**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| token | string | Yes | Password reset token received via email |
| password | string | Yes | New password (min 8 characters recommended) |

**Success Response** (200 OK):
```json
{
  "message": "Password has been reset successfully"
}
```

**Error Responses**:

**400 Bad Request** - Invalid request format:
```json
{
  "error": "Invalid request payload"
}
```

**400 Bad Request** - Invalid or expired token:
```json
{
  "error": "invalid or expired reset token"
}
```

**400 Bad Request** - Token has expired:
```json
{
  "error": "reset token has expired"
}
```

**500 Internal Server Error** - Server error:
```json
{
  "error": "Failed to reset password"
}
```

**Example Request**:

```bash
curl -X POST http://localhost:8080/api/auth/password-reset/confirm \
  -H "Content-Type: application/json" \
  -d '{
    "token": "abc123def456...",
    "password": "MyNewSecurePassword123!"
  }'
```

**Example Response**:
```json
{
  "message": "Password has been reset successfully"
}
```

## Error Response Format

All error responses follow this format:

```json
{
  "error": "Error message describing what went wrong"
}
```

## Status Codes

| Code | Meaning |
|------|---------|
| 200  | OK - Request succeeded |
| 400  | Bad Request - Invalid request format |
| 500  | Internal Server Error - Server error |

## Security Considerations

- Password reset tokens should be short-lived (typically 15-60 minutes)
- Tokens should be single-use and invalidated after use
- Email responses are generic to prevent email enumeration attacks
- Passwords are hashed using bcrypt before storage

---

**Last Updated**: January 11, 2026