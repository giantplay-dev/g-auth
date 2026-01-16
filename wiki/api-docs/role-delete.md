# Delete Role

## Overview

Delete a role from the system. This endpoint requires admin privileges.

## Base Information

- **Base URL**: `http://localhost:8080`
- **API Version**: v1
- **Authentication**: Required (Admin role)
- **Content-Type**: `application/json`

## Endpoint

**Endpoint**: `DELETE /api/roles/{id}`

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
  "message": "Role deleted successfully"
}
```

**Response Fields**:

| Field | Type | Description |
|-------|------|-------------|
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

**Invalid UUID** (400):
```json
{
  "error": "Invalid role ID"
}
```

## Example Usage

### cURL
```bash
curl -X DELETE http://localhost:8080/api/roles/123e4567-e89b-12d3-a456-426614174000 \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### JavaScript (Fetch)
```javascript
const roleId = '123e4567-e89b-12d3-a456-426614174000';
const response = await fetch(`http://localhost:8080/api/roles/${roleId}`, {
  method: 'DELETE',
  headers: {
    'Authorization': `Bearer ${accessToken}`
  }
});

const data = await response.json();
```

## Notes

- Only users with admin role can delete roles
- Deleting a role will remove all role assignments from users
- Default roles (admin, user, moderator) should not be deleted
- This operation cannot be undone
- The role ID must be a valid UUID format
