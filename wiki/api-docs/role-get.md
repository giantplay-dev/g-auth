# Get Role by ID

## Overview

Retrieve a specific role by its ID with all associated permissions. This endpoint requires authentication.

## Base Information

- **Base URL**: `http://localhost:8080`
- **API Version**: v1
- **Authentication**: Required
- **Content-Type**: `application/json`

## Endpoint

**Endpoint**: `GET /api/roles/{id}`

## Request

**Request Headers**:
```
Authorization: Bearer <access_token>
```

**Path Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| id | UUID | Yes | Unique role identifier |

## Response

**Success Response** (200 OK):
```json
{
  "role": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "name": "admin",
    "description": "Administrator with full system access",
    "permissions": [
      {
        "id": "223e4567-e89b-12d3-a456-426614174000",
        "name": "user:read",
        "description": "Read user information",
        "resource": "user",
        "action": "read",
        "created_at": "2026-01-16T10:00:00Z",
        "updated_at": "2026-01-16T10:00:00Z"
      },
      {
        "id": "323e4567-e89b-12d3-a456-426614174000",
        "name": "user:write",
        "description": "Create and update users",
        "resource": "user",
        "action": "write",
        "created_at": "2026-01-16T10:00:00Z",
        "updated_at": "2026-01-16T10:00:00Z"
      },
      {
        "id": "423e4567-e89b-12d3-a456-426614174000",
        "name": "system:admin",
        "description": "Full system administration access",
        "resource": "system",
        "action": "admin",
        "created_at": "2026-01-16T10:00:00Z",
        "updated_at": "2026-01-16T10:00:00Z"
      }
    ],
    "created_at": "2026-01-16T10:00:00Z",
    "updated_at": "2026-01-16T10:00:00Z"
  }
}
```

**Response Fields**:

| Field | Type | Description |
|-------|------|-------------|
| role.id | UUID | Unique role identifier |
| role.name | string | Role name |
| role.description | string | Role description |
| role.permissions | array | Array of permission objects |
| role.created_at | timestamp | Role creation timestamp |
| role.updated_at | timestamp | Last update timestamp |

## Error Responses

**Unauthorized** (401):
```json
{
  "error": "Unauthorized"
}
```

**Role Not Found** (404):
```json
{
  "error": "role not found"
}
```

**Invalid UUID** (400):
```json
{
  "error": "Invalid role ID"
}
```

## Example Usage

### cURL
```bash
curl -X GET http://localhost:8080/api/roles/123e4567-e89b-12d3-a456-426614174000 \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### JavaScript (Fetch)
```javascript
const roleId = '123e4567-e89b-12d3-a456-426614174000';
const response = await fetch(`http://localhost:8080/api/roles/${roleId}`, {
  method: 'GET',
  headers: {
    'Authorization': `Bearer ${accessToken}`
  }
});

const data = await response.json();
```

## Notes

- Any authenticated user can retrieve role details
- The role ID must be a valid UUID format
- The response includes all permissions associated with the role
