# Get User Roles

## Overview

Retrieve all roles assigned to a specific user. This endpoint requires authentication.

## Base Information

- **Base URL**: `http://localhost:8080`
- **API Version**: v1
- **Authentication**: Required
- **Content-Type**: `application/json`

## Endpoint

**Endpoint**: `GET /api/users/{user_id}/roles`

## Request

**Request Headers**:
```
Authorization: Bearer <access_token>
```

**Path Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| user_id | UUID | Yes | Unique user identifier |

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
      "name": "moderator",
      "description": "Moderator with elevated permissions",
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

**User Not Found** (404):
```json
{
  "error": "user not found"
}
```

**Invalid UUID** (400):
```json
{
  "error": "Invalid user ID"
}
```

## Example Usage

### cURL
```bash
curl -X GET http://localhost:8080/api/users/550e8400-e29b-41d4-a716-446655440000/roles \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### JavaScript (Fetch)
```javascript
const userId = '550e8400-e29b-41d4-a716-446655440000';
const response = await fetch(`http://localhost:8080/api/users/${userId}/roles`, {
  method: 'GET',
  headers: {
    'Authorization': `Bearer ${accessToken}`
  }
});

const data = await response.json();
```

## Notes

- Any authenticated user can retrieve their own roles
- Admin users can retrieve roles for any user
- Roles are returned in alphabetical order by name
- Each role includes its associated permissions
- Users without any roles will return an empty array
