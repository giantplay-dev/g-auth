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
  "message": "Registration successful. Please check your email to verify your account."
}
```

**Response Fields**:

| Field | Type | Description |
|-------|------|-------------|
| message | string | Confirmation message indicating registration was successful and verification email was sent |

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
  "message": "Registration successful. Please check your email to verify your account."
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