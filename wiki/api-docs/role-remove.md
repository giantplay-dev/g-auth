# Remove Role from User

## Overview

Remove a role from a user. This endpoint requires admin privileges.

## Base Information

- **Base URL**: `http://localhost:8080`
- **API Version**: v1
- **Authentication**: Required (Admin role)
- **Content-Type**: `application/json`

## Endpoint

**Endpoint**: `POST /api/roles/remove`

## Request

**Request Headers**:
```
Content-Type: application/json
Authorization: Bearer <access_token>
```

**Request Body**:
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "role_id": "660e8400-e29b-41d4-a716-446655440000"
}
```

**Request Fields**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| user_id | UUID | Yes | ID of the user to remove the role from |
| role_id | UUID | Yes | ID of the role to remove |

## Response

**Success Response** (200 OK):
```json
{
  "message": "Role removed from user successfully"
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

**Invalid Request** (400):
```json
{
  "error": "Invalid request body"
}
```

## Example Usage

### cURL
```bash
curl -X POST http://localhost:8080/api/roles/remove \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -d '{
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "role_id": "660e8400-e29b-41d4-a716-446655440000"
  }'
```

### JavaScript (Fetch)
```javascript
const response = await fetch('http://localhost:8080/api/roles/remove', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${accessToken}`
  },
  body: JSON.stringify({
    user_id: '550e8400-e29b-41d4-a716-446655440000',
    role_id: '660e8400-e29b-41d4-a716-446655440000'
  })
});

const data = await response.json();
```

## Notes

- Only users with admin role can remove roles from users
- Removing a non-existent role assignment has no effect (idempotent)
- Both user_id and role_id must be valid UUIDs
- The role will be immediately removed from the user
- Users should have at least one role assigned
