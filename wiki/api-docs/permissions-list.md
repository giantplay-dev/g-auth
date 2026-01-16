# Get All Permissions

## Overview

Retrieve a list of all available permissions in the system. This endpoint requires authentication.

## Base Information

- **Base URL**: `http://localhost:8080`
- **API Version**: v1
- **Authentication**: Required
- **Content-Type**: `application/json`

## Endpoint

**Endpoint**: `GET /api/permissions`

## Request

**Request Headers**:
```
Authorization: Bearer <access_token>
```

## Response

**Success Response** (200 OK):
```json
{
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
      "name": "user:delete",
      "description": "Delete users",
      "resource": "user",
      "action": "delete",
      "created_at": "2026-01-16T10:00:00Z",
      "updated_at": "2026-01-16T10:00:00Z"
    },
    {
      "id": "523e4567-e89b-12d3-a456-426614174000",
      "name": "role:read",
      "description": "Read role information",
      "resource": "role",
      "action": "read",
      "created_at": "2026-01-16T10:00:00Z",
      "updated_at": "2026-01-16T10:00:00Z"
    },
    {
      "id": "623e4567-e89b-12d3-a456-426614174000",
      "name": "role:write",
      "description": "Create and update roles",
      "resource": "role",
      "action": "write",
      "created_at": "2026-01-16T10:00:00Z",
      "updated_at": "2026-01-16T10:00:00Z"
    },
    {
      "id": "723e4567-e89b-12d3-a456-426614174000",
      "name": "role:delete",
      "description": "Delete roles",
      "resource": "role",
      "action": "delete",
      "created_at": "2026-01-16T10:00:00Z",
      "updated_at": "2026-01-16T10:00:00Z"
    },
    {
      "id": "823e4567-e89b-12d3-a456-426614174000",
      "name": "system:admin",
      "description": "Full system administration access",
      "resource": "system",
      "action": "admin",
      "created_at": "2026-01-16T10:00:00Z",
      "updated_at": "2026-01-16T10:00:00Z"
    }
  ]
}
```

**Response Fields**:

| Field | Type | Description |
|-------|------|-------------|
| permissions | array | Array of permission objects |
| permissions[].id | UUID | Unique permission identifier |
| permissions[].name | string | Permission name (format: resource:action) |
| permissions[].description | string | Permission description |
| permissions[].resource | string | Resource the permission applies to |
| permissions[].action | string | Action allowed on the resource |
| permissions[].created_at | timestamp | Permission creation timestamp |
| permissions[].updated_at | timestamp | Last update timestamp |

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
curl -X GET http://localhost:8080/api/permissions \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### JavaScript (Fetch)
```javascript
const response = await fetch('http://localhost:8080/api/permissions', {
  method: 'GET',
  headers: {
    'Authorization': `Bearer ${accessToken}`
  }
});

const data = await response.json();
```

## Notes

- Any authenticated user can retrieve the list of permissions
- Permissions are returned ordered by resource and action
- System includes default permissions for user, role, and system resources
- Permission names follow the format: `resource:action`
- Permissions are used to define what actions a role can perform

## Default Permissions

The system includes these default permissions:

### User Permissions
- `user:read` - Read user information
- `user:write` - Create and update users
- `user:delete` - Delete users

### Role Permissions
- `role:read` - Read role information
- `role:write` - Create and update roles
- `role:delete` - Delete roles

### System Permissions
- `system:admin` - Full system administration access
