# Enable MFA API

## Enable Multi-Factor Authentication

Enables multi-factor authentication for the authenticated user's account.

### Endpoint

```
POST /api/mfa/enable
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
  "message": "Multi-factor authentication has been enabled successfully"
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

#### MFA Already Enabled

**Code:** `400 Bad Request`

```json
{
  "error": "MFA is already enabled"
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
- Once enabled, MFA will be required for all future logins
- A 6-digit code will be sent via email during each login attempt
- MFA codes expire after 10 minutes

### Example Usage

```bash
# Enable MFA
curl -X POST http://localhost:8080/api/mfa/enable \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -d '{
    "password": "MySecurePassword123!"
  }'
```

### Integration Flow

1. User logs in and obtains JWT token
2. User navigates to security settings
3. User clicks "Enable MFA"
4. User enters their current password
5. System verifies password and enables MFA
6. Future logins will require MFA code verification

### Security Considerations

- Password verification prevents unauthorized MFA changes if someone gains access to an active session
- Once enabled, MFA codes will be required for all login attempts
- Keep your email account secure as it will be used to receive MFA codes
- Consider implementing backup codes in future versions for account recovery
