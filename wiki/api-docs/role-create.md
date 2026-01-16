# Create Role

## Overview

Create a new role with specified permissions. This endpoint requires admin privileges.

## Base Information

- **Base URL**: `http://localhost:8080`
- **API Version**: v1
- **Authentication**: Required (Admin role)
- **Content-Type**: `application/json`

## Endpoint

**Endpoint**: `POST /api/roles`

## Request

**Request Headers**:
```
Content-Type: application/json
Authorization: Bearer <access_token>
```

**Request Body**:
```json
{
  "name": "editor",
  "description": "Content editor role",
  "permissions": ["user:read", "user:write"]
}
```

**Request Fields**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | Unique role name (lowercase, no spaces) |
| description | string | No | Human-readable role description |
| permissions | array | No | Array of permission names to assign |

## Response

**Success Response** (201 Created):
```json
{
  "role": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "editor",
    "description": "Content editor role",
    "permissions": [
      {
        "id": "660e8400-e29b-41d4-a716-446655440000",
        "name": "user:read",
        "description": "Read user information",
        "resource": "user",
        "action": "read",
        "created_at": "2026-01-16T10:00:00Z",
        "updated_at": "2026-01-16T10:00:00Z"
      },
      {
        "id": "770e8400-e29b-41d4-a716-446655440000",
        "name": "user:write",
        "description": "Create and update users",
        "resource": "user",
        "action": "write",
        "created_at": "2026-01-16T10:00:00Z",
        "updated_at": "2026-01-16T10:00:00Z"
      }
    ],
    "created_at": "2026-01-16T10:00:00Z",
    "updated_at": "2026-01-16T10:00:00Z"
  },
  "message": "Role created successfully"
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

**Role Already Exists** (400):
```json
{
  "error": "role already exists"
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
curl -X POST http://localhost:8080/api/roles \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -d '{
    "name": "editor",
    "description": "Content editor role",
    "permissions": ["user:read", "user:write"]
  }'
```

### JavaScript (Fetch)
```javascript
const response = await fetch('http://localhost:8080/api/roles', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${accessToken}`
  },
  body: JSON.stringify({
    name: 'editor',
    description: 'Content editor role',
    permissions: ['user:read', 'user:write']
  })
});

const data = await response.json();
```

## Notes

- Only users with admin role can create roles
- Role names must be unique
- Role names should be lowercase without spaces
- Permissions are optional during role creation
- Invalid permission names will be ignored
- Default roles (admin, user, moderator) cannot be recreated
