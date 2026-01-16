# Update Role

## Overview

Update a role's description and permissions. This endpoint requires admin privileges.

## Base Information

- **Base URL**: `http://localhost:8080`
- **API Version**: v1
- **Authentication**: Required (Admin role)
- **Content-Type**: `application/json`

## Endpoint

**Endpoint**: `PUT /api/roles/{id}`

## Request

**Request Headers**:
```
Content-Type: application/json
Authorization: Bearer <access_token>
```

**Path Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| id | UUID | Yes | Unique role identifier |

**Request Body**:
```json
{
  "description": "Updated role description",
  "permissions": ["user:read", "user:write", "role:read"]
}
```

**Request Fields**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| description | string | No | Updated role description |
| permissions | array | No | Array of permission names (replaces existing permissions) |

## Response

**Success Response** (200 OK):
```json
{
  "role": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "name": "editor",
    "description": "Updated role description",
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
        "name": "role:read",
        "description": "Read role information",
        "resource": "role",
        "action": "read",
        "created_at": "2026-01-16T10:00:00Z",
        "updated_at": "2026-01-16T10:00:00Z"
      }
    ],
    "created_at": "2026-01-16T10:00:00Z",
    "updated_at": "2026-01-16T10:05:00Z"
  },
  "message": "Role updated successfully"
}
```

**Response Fields**:

| Field | Type | Description |
|-------|------|-------------|
| role.id | UUID | Unique role identifier |
| role.name | string | Role name (cannot be changed) |
| role.description | string | Updated role description |
| role.permissions | array | Array of permission objects |
| role.created_at | timestamp | Role creation timestamp |
| role.updated_at | timestamp | Last update timestamp |
| message | string | Success message |

## Error Responses

**Unauthorized** (401):
```json
{
  "error": "Unauthorized"
}
```

**Forbidden** (403):
```json
{
  "error": "Forbidden: insufficient role permissions"
}
```

**Role Not Found** (404):
```json
{
  "error": "role not found"
}
```

**Invalid Request** (400):
```json
{
  "error": "Invalid request body"
}
```

## Example Usage

### cURL
```bash
curl -X PUT http://localhost:8080/api/roles/123e4567-e89b-12d3-a456-426614174000 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -d '{
    "description": "Updated role description",
    "permissions": ["user:read", "user:write", "role:read"]
  }'
```

### JavaScript (Fetch)
```javascript
const roleId = '123e4567-e89b-12d3-a456-426614174000';
const response = await fetch(`http://localhost:8080/api/roles/${roleId}`, {
  method: 'PUT',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${accessToken}`
  },
  body: JSON.stringify({
    description: 'Updated role description',
    permissions: ['user:read', 'user:write', 'role:read']
  })
});

const data = await response.json();
```

## Notes

- Only users with admin role can update roles
- Role name cannot be changed after creation
- Permissions array replaces all existing permissions
- Invalid permission names will be ignored
- At least one field (description or permissions) must be provided
