# Get All Roles

## Overview

Retrieve a list of all roles in the system with their permissions. This endpoint requires authentication.

## Base Information

- **Base URL**: `http://localhost:8080`
- **API Version**: v1
- **Authentication**: Required
- **Content-Type**: `application/json`

## Endpoint

**Endpoint**: `GET /api/roles`

## Request

**Request Headers**:
```
Authorization: Bearer <access_token>
```

## Response

**Success Response** (200 OK):
```json
{
  "roles": [
    {
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
    },
    {
      "id": "523e4567-e89b-12d3-a456-426614174000",
      "name": "user",
      "description": "Standard user with basic permissions",
      "permissions": [
        {
          "id": "223e4567-e89b-12d3-a456-426614174000",
          "name": "user:read",
          "description": "Read user information",
          "resource": "user",
          "action": "read",
          "created_at": "2026-01-16T10:00:00Z",
          "updated_at": "2026-01-16T10:00:00Z"
        }
      ],
      "created_at": "2026-01-16T10:00:00Z",
      "updated_at": "2026-01-16T10:00:00Z"
    }
  ]
}
```

**Response Fields**:

| Field | Type | Description |
|-------|------|-------------|
| roles | array | Array of role objects |
| roles[].id | UUID | Unique role identifier |
| roles[].name | string | Role name |
| roles[].description | string | Role description |
| roles[].permissions | array | Array of permission objects |
| roles[].created_at | timestamp | Role creation timestamp |
| roles[].updated_at | timestamp | Last update timestamp |

## Error Responses

**Unauthorized** (401):
```json
{
  "error": "Unauthorized"
}
```

## Example Usage

### cURL
```bash
curl -X GET http://localhost:8080/api/roles \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### JavaScript (Fetch)
```javascript
const response = await fetch('http://localhost:8080/api/roles', {
  method: 'GET',
  headers: {
    'Authorization': `Bearer ${accessToken}`
  }
});

const data = await response.json();
```

## Notes

- Any authenticated user can retrieve the list of roles
- Roles are returned in alphabetical order by name
- Each role includes its associated permissions
- System includes three default roles: admin, user, moderator
