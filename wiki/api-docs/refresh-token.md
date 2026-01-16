# Refresh Token

## Overview

The authentication service supports refresh tokens to provide better security and user experience. Refresh tokens allow users to obtain new access tokens without re-authenticating, while access tokens remain short-lived for security.

## Base Information

- **Base URL**: `http://localhost:8080`
- **API Version**: v1
- **Authentication**: None required
- **Content-Type**: `application/json`

## Architecture

### Token Types

1. **Access Token**: Short-lived JWT (15 minutes) used for API authentication
2. **Refresh Token**: Long-lived JWT (7 days) used to obtain new access tokens

### Database Changes

Added two new columns to the `users` table:
- `refresh_token`: Stores the current refresh token (hashed)
- `refresh_token_expires_at`: Stores the expiration timestamp

### JWT Manager Extensions

The JWT manager now supports:
- Generating refresh tokens with longer expiration
- Verifying refresh tokens
- Separate expiration times for access and refresh tokens

## Endpoint

**Endpoint**: `POST /api/auth/refresh`

## Request

**Request Headers**:
```
Content-Type: application/json
```

**Request Body**:
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Request Fields**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| refresh_token | string | Yes | Valid refresh token obtained from login/register |

## Response

**Success Response** (200 OK):
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMTIzZTQ1NjctZTg5Yi0xMmQzLWE0NTYtNDI2NjE0MTc0MDAwIiwiZXhwIjoxNzM2NTA1NjAwfQ.abc123...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMTIzZTQ1NjctZTg5Yi0xMmQzLWE0NTYtNDI2NjE0MTc0MDAwIiwiZXhwIjoxNzM3MTEwNDAwfQ.def456...",
  "user": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "email": "user@example.com",
    "name": "John Doe",
    "email_verified": true,
    "created_at": "2026-01-10T10:00:00Z",
    "updated_at": "2026-01-10T10:00:00Z"
  }
}
```

**Response Fields**:

| Field | Type | Description |
|-------|------|-------------|
| token | string | New JWT access token (15 minutes expiration) |
| refresh_token | string | New JWT refresh token (7 days expiration) |
| user.id | string (UUID) | Unique user identifier |
| user.email | string | User's email address |
| user.name | string | User's full name |
| user.email_verified | boolean | Whether the user's email has been verified |
| user.created_at | string (ISO 8601) | Account creation timestamp |
| user.updated_at | string (ISO 8601) | Last update timestamp |

## Error Responses

All error responses follow this format:

```json
{
  "error": "Error message describing what went wrong"
}
```

**Status Codes**:

| Code | Meaning |
|------|---------|
| 200  | OK - Request succeeded |
| 400  | Bad Request - Invalid request format |
| 401  | Unauthorized - Missing or invalid authentication |

**400 Bad Request** - Invalid request format:
```json
{
  "error": "Invalid request payload"
}
```

**401 Unauthorized** - Invalid or expired refresh token:
```json
{
  "error": "invalid credentials"
}
```

## Example

**Example Request**:

```bash
curl -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'
```

**Example Response**:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "email": "user@example.com",
    "name": "User Name",
    "email_verified": true,
    "created_at": "2026-01-10T15:30:00Z",
    "updated_at": "2026-01-10T15:30:00Z"
  }
}
```

## Security Considerations

### Token Expiration
- Access tokens: 15 minutes
- Refresh tokens: 7 days

### Token Rotation
Each refresh operation generates new access and refresh tokens, invalidating the previous refresh token.

### Database Storage
Refresh tokens are stored hashed in the database for additional security.

## Usage Flow

1. User logs in or registers → receives access token + refresh token
2. When access token expires, client sends refresh token to `/api/auth/refresh`
3. Server validates refresh token and returns new token pair
4. Client uses new access token for API calls
5. Repeat step 2-4 as needed

## Implementation Details

### Service Methods

- `RefreshToken(ctx, req)`: Main refresh logic
- Validates refresh token JWT
- Retrieves user by refresh token from database
- Checks token expiration
- Generates new token pair
- Updates database with new refresh token

### Repository Methods

- `UpdateRefreshToken(userID, token, expiresAt)`: Store refresh token
- `GetByRefreshToken(token)`: Retrieve user by refresh token
- `ClearRefreshToken(userID)`: Remove refresh token (logout)

### Configuration

Added `RefreshTokenExpiration` to config:
```go
RefreshTokenExpiration: 7 * 24 * time.Hour // 7 days
```

## JWT Token Structure

The JWT token consists of three parts separated by dots:

```
header.payload.signature
```

### Header
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

### Payload (Claims)
```json
{
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "exp": 1736505600
}
```

### Token Expiration

- **Access Token Expiration**: 15 minutes (configurable)
- **Refresh Token Expiration**: 7 days (configurable)
- **Expiration Field**: `exp` (Unix timestamp)
- **After Expiration**: Token becomes invalid and returns 401 Unauthorized

---

**Last Updated**: January 11, 2026