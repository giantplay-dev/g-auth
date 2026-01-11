# Get Current User Profile

## Overview

Retrieve the authenticated user's profile information.

## Base Information

- **Base URL**: `http://localhost:8080`
- **API Version**: v1
- **Authentication**: JWT Bearer Token required
- **Content-Type**: `application/json`

## Authentication

Protected endpoints require a JWT token in the Authorization header:

```
Authorization: Bearer <jwt-token>
```

## Endpoint

**Endpoint**: `GET /api/me`

## Request

**Request Headers**:
```
Authorization: Bearer <jwt-token>
```

**Request Body**: None

## Response

**Success Response** (200 OK):
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "email": "user@example.com",
  "name": "John Doe",
  "created_at": "2026-01-10T10:00:00Z",
  "updated_at": "2026-01-10T10:00:00Z"
}
```

**Response Fields**:

| Field | Type | Description |
|-------|------|-------------|
| id | string (UUID) | Unique user identifier |
| email | string | User's email address |
| name | string | User's full name |
| created_at | string (ISO 8601) | Account creation timestamp |
| updated_at | string (ISO 8601) | Last update timestamp |

**Note**: The `password` field is never returned in any response.

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
| 401  | Unauthorized - Missing or invalid authentication |
| 404  | Not Found - Resource not found |

**401 Unauthorized** - Missing or invalid token:
```json
{
  "error": "missing or invalid authorization header"
}
```

**401 Unauthorized** - Invalid token:
```json
{
  "error": "invalid token"
}
```

**404 Not Found** - User not found:
```json
{
  "error": "User not found"
}
```

## Example

**Example Request**:

```bash
curl -X GET http://localhost:8080/api/me \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Example Response**:
```json
{
  "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "email": "john.doe@example.com",
  "name": "John Doe",
  "created_at": "2026-01-10T15:30:00Z",
  "updated_at": "2026-01-10T15:30:00Z"
}
```

## Protected Route Access

```
1. Client sends request with Authorization header
   └── Authorization: Bearer <token>

2. Auth middleware validates token
   ├── Extracts token from header
   ├── Verifies token signature
   ├── Checks expiration
   ├── Extracts user_id from claims
   └── Adds user_id to request context

3. Handler processes request
   ├── Retrieves user_id from context
   ├── Performs business logic
   └── Returns response
```

---

**Last Updated**: January 11, 2026