# Verify Email

## Overview

Verify a user's email address using the verification token sent via email.

## Base Information

- **Base URL**: `http://localhost:8080`
- **API Version**: v1
- **Authentication**: None required
- **Content-Type**: `application/json`

## Endpoint

**Endpoint**: `POST /api/auth/verify-email`

## Request

**Request Headers**:
```
Content-Type: application/json
```

**Request Body**:
```json
{
  "token": "abc123def456..."
}
```

**Request Fields**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| token | string | Yes | Verification token received via email |

## Response

**Success Response** (200 OK):
```json
{
  "message": "Email verified successfully. You can now log in."
}
```

**Response Fields**:

| Field | Type | Description |
|-------|------|-------------|
| message | string | Confirmation message indicating email was verified |

## Error Responses

All error responses follow this format:

```json
{
  "error": "Error message describing what went wrong"
}
```

**Common Error Responses**:

- **400 Bad Request**: Invalid or expired verification token
  ```json
  {
    "error": "invalid or expired verification token"
  }
  ```

- **400 Bad Request**: Token has expired
  ```json
  {
    "error": "verification token has expired"
  }
  ```

## Example Usage

```bash
curl -X POST http://localhost:8080/api/auth/verify-email \
  -H "Content-Type: application/json" \
  -d '{
    "token": "abc123def456..."
  }'
```

## Notes

- Verification tokens expire after 24 hours
- Once verified, the email cannot be unverified
- Users must verify their email before they can log in</content>
<parameter name="filePath">/home/giantplay/Playground/g-modules/g-auth/wiki/api-docs/verify-email.md