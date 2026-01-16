# Assign Role to User

## Overview

Assign a role to a user. This endpoint requires admin privileges.

## Base Information

- **Base URL**: `http://localhost:8080`
- **API Version**: v1
- **Authentication**: Required (Admin role)
- **Content-Type**: `application/json`

## Endpoint

**Endpoint**: `POST /api/roles/assign`

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
| user_id | UUID | Yes | ID of the user to assign the role to |
| role_id | UUID | Yes | ID of the role to assign |

## Response

**Success Response** (200 OK):
```json
{
  "message": "Role assigned to user successfully"
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

**User Not Found** (404):
```json
{
  "error": "user not found"
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
curl -X POST http://localhost:8080/api/roles/assign \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -d '{
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "role_id": "660e8400-e29b-41d4-a716-446655440000"
  }'
```

### JavaScript (Fetch)
```javascript
const response = await fetch('http://localhost:8080/api/roles/assign', {
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

- Only users with admin role can assign roles to users
- A user can have multiple roles
- Assigning the same role twice has no effect (idempotent)
- Both user_id and role_id must be valid UUIDs
- The role will be immediately active for the user
