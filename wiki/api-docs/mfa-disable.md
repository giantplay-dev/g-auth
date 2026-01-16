# Disable MFA API

## Disable Multi-Factor Authentication

Disables multi-factor authentication for the authenticated user's account.

### Endpoint

```
POST /api/mfa/disable
```

### Request Headers

```
Content-Type: application/json
Authorization: Bearer <jwt_token>
```

### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| password | string | Yes | User's current password for verification |

### Example Request

```json
{
  "password": "MySecurePassword123!"
}
```

### Success Response

**Code:** `200 OK`

**Response Body:**

```json
{
  "message": "Multi-factor authentication has been disabled successfully"
}
```

### Error Responses

#### Invalid Password

**Code:** `401 Unauthorized`

```json
{
  "error": "Invalid email or password"
}
```

#### MFA Not Enabled

**Code:** `400 Bad Request`

```json
{
  "error": "MFA is not enabled"
}
```

#### Unauthorized

**Code:** `401 Unauthorized`

```json
{
  "error": "Unauthorized"
}
```

#### Invalid Request

**Code:** `400 Bad Request`

```json
{
  "error": "Invalid request payload"
}
```

### Notes

- Requires a valid JWT token in the Authorization header
- Password verification is required for security purposes
- Once disabled, users can log in with just email and password
- Any pending MFA codes are cleared when MFA is disabled

### Example Usage

```bash
# Disable MFA
curl -X POST http://localhost:8080/api/mfa/disable \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -d '{
    "password": "MySecurePassword123!"
  }'
```

### Integration Flow

1. User logs in and obtains JWT token
2. User navigates to security settings
3. User clicks "Disable MFA"
4. User enters their current password
5. System verifies password and disables MFA
6. Future logins will not require MFA code verification

### Security Considerations

- Password verification prevents unauthorized MFA changes if someone gains access to an active session
- Disabling MFA reduces account security - users should be warned about this
- Consider requiring email verification or additional confirmation before allowing MFA to be disabled
- All pending MFA codes are invalidated when MFA is disabled
