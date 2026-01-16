# Resend Verification Email

## Overview

Resend the email verification link to a user's email address.

## Base Information

- **Base URL**: `http://localhost:8080`
- **API Version**: v1
- **Authentication**: None required
- **Content-Type**: `application/json`

## Endpoint

**Endpoint**: `POST /api/auth/resend-verification`

## Request

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
| email | string | Yes | User's email address |

## Response

**Success Response** (200 OK):
```json
{
  "message": "Verification email sent successfully."
}
```

**Response Fields**:

| Field | Type | Description |
|-------|------|-------------|
| message | string | Confirmation message indicating verification email was sent |

## Error Responses

All error responses follow this format:

```json
{
  "error": "Error message describing what went wrong"
}
```

**Common Error Responses**:

- **404 Not Found**: User not found
  ```json
  {
    "error": "user not found"
  }
  ```

- **200 OK**: Email already verified
  ```json
  {
    "message": "Email is already verified."
  }
  ```

## Example Usage

```bash
curl -X POST http://localhost:8080/api/auth/resend-verification \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com"
  }'
```

## Notes

- If the email is already verified, returns a success message
- Generates a new verification token with a fresh 24-hour expiration
- Can be called multiple times without restriction</content>
<parameter name="filePath">/home/giantplay/Playground/g-modules/g-auth/wiki/api-docs/resend-verification.md