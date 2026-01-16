# MFA Status API

## Get MFA Status

Retrieves the current MFA status for the authenticated user.

### Endpoint

```
GET /api/mfa/status
```

### Request Headers

```
Authorization: Bearer <jwt_token>
```

### Success Response

**Code:** `200 OK`

**Response Body:**

```json
{
  "mfa_enabled": true
}
```

or

```json
{
  "mfa_enabled": false
}
```

### Error Responses

#### User Not Found

**Code:** `404 Not Found`

```json
{
  "error": "user not found"
}
```

#### Unauthorized

**Code:** `401 Unauthorized`

```json
{
  "error": "Unauthorized"
}
```

### Notes

- Requires a valid JWT token in the Authorization header
- Returns the current MFA status for the authenticated user
- This endpoint can be used to display MFA status in user settings

### Example Usage

```bash
# Get MFA status
curl -X GET http://localhost:8080/api/mfa/status \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Integration Flow

1. User logs in and obtains JWT token
2. Frontend displays user security settings
3. Frontend calls this endpoint to get current MFA status
4. Display "Enable MFA" or "Disable MFA" button based on the status

### Use Cases

- Display MFA status in user profile/settings
- Conditionally show enable/disable MFA options
- Security dashboard showing active security features
- Onboarding flow to encourage users to enable MFA
