# Register User

## Overview

Create a new user account in the authentication service.

## Base Information

- **Base URL**: `http://localhost:8080`
- **API Version**: v1
- **Authentication**: None required
- **Content-Type**: `application/json`

## Endpoint

**Endpoint**: `POST /api/auth/register`

## Request

**Request Headers**:
```
Content-Type: application/json
```

**Request Body**:
```json
{
  "email": "user@example.com",
  "password": "SecureP@ssw0rd",
  "name": "John Doe"
}
```

**Request Fields**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| email | string | Yes | User's email address (must be unique) |
| password | string | Yes | User's password (min 8 characters recommended) |
| name | string | Yes | User's full name |

## Response

**Success Response** (201 Created):
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
| 201  | Created - Resource created successfully |
| 400  | Bad Request - Invalid request format |
| 409  | Conflict - Resource already exists |
| 500  | Internal Server Error - Server error |

**400 Bad Request** - Invalid request format:
```json
{
  "error": "Invalid request payload"
}
```

**409 Conflict** - Email already exists:
```json
{
  "error": "user already exists"
}
```

**500 Internal Server Error** - Server error:
```json
{
  "error": "Failed to register user"
}
```

## Example

**Example Request**:

```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com",
    "password": "MySecurePassword123!",
    "name": "John Doe"
  }'
```

**Example Response**:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
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

### Registration Flow

```
1. POST /api/auth/register
   ├── Server validates request format
   ├── Server checks if email already exists
   ├── Server hashes password with bcrypt
   ├── Server creates user in database
   ├── Server generates JWT token
   └── Server returns token + user data

2. Client stores JWT token
3. Client includes token in subsequent requests
```

---

**Last Updated**: January 11, 2026