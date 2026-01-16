# Login

## Overview

Authenticate a user and receive JWT tokens for accessing protected endpoints.

## Base Information

- **Base URL**: `http://localhost:8080`
- **API Version**: v1
- **Authentication**: None required
- **Content-Type**: `application/json`

## Endpoint

**Endpoint**: `POST /api/auth/login`

## Request

**Request Headers**:
```
Content-Type: application/json
```

**Request Body**:
```json
{
  "email": "user@example.com",
  "password": "SecureP@ssw0rd"
}
```

**Request Fields**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| email | string | Yes | User's registered email address |
| password | string | Yes | User's password |

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
    "created_at": "2026-01-10T10:00:00Z",
    "updated_at": "2026-01-10T10:00:00Z"
  }
}
```

**Response Fields**:

| Field | Type | Description |
|-------|------|-------------|
| token | string | JWT access token (15 minutes expiration) |
| refresh_token | string | JWT refresh token (7 days expiration) |
| user.id | string (UUID) | Unique user identifier |
| user.email | string | User's email address |
| user.name | string | User's full name |
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
| 403  | Forbidden - Email not verified |
| 500  | Internal Server Error - Server error |

**400 Bad Request** - Invalid request format:
```json
{
  "error": "Invalid request payload"
}
```

**401 Unauthorized** - Invalid credentials:
```json
{
  "error": "invalid credentials"
}
```

**403 Forbidden** - Email not verified:
```json
{
  "error": "email not verified"
}
```

**500 Internal Server Error** - Server error:
```json
{
  "error": "Failed to login"
}
```

## Example

**Example Request**:

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com",
    "password": "MySecurePassword123!"
  }'
```

**Example Response**:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "email": "john.doe@example.com",
    "name": "John Doe",
    "created_at": "2026-01-10T15:30:00Z",
    "updated_at": "2026-01-10T15:30:00Z"
  }
}
```

## Authentication Flow

### Login Flow

```
1. POST /api/auth/login
   ├── Server validates request format
   ├── Server fetches user by email
   ├── Server verifies password with bcrypt
   ├── Server generates JWT token
   └── Server returns token + user data

2. Client stores JWT token
3. Client includes token in subsequent requests
```

---

**Last Updated**: January 11, 2026