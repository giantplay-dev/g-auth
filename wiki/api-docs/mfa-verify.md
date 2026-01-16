# MFA Verification API

## Verify MFA Code

Verifies the multi-factor authentication code sent via email after login.

### Endpoint

```
POST /api/auth/mfa/verify
```

### Request Headers

```
Content-Type: application/json
```

### Request Body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| email | string | Yes | User's email address |
| code | string | Yes | 6-digit MFA code received via email |

### Example Request

```json
{
  "email": "user@example.com",
  "code": "123456"
}
```

### Success Response

**Code:** `200 OK`

**Response Body:**

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "name": "John Doe",
    "email_verified": true,
    "mfa_enabled": true,
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z"
  }
}
```

### Error Responses

#### Invalid MFA Code

**Code:** `401 Unauthorized`

```json
{
  "error": "invalid or expired MFA code"
}
```

#### Expired MFA Code

**Code:** `401 Unauthorized`

```json
{
  "error": "MFA code has expired"
}
```

#### MFA Not Enabled

**Code:** `400 Bad Request`

```json
{
  "error": "MFA is not enabled"
}
```

#### Invalid Credentials

**Code:** `401 Unauthorized`

```json
{
  "error": "Invalid email or password"
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

- The MFA code expires after 10 minutes
- After successful verification, the MFA code is cleared from the system
- The returned JWT token should be used for subsequent authenticated requests
- The refresh token can be used to obtain a new access token when it expires

### Example Usage

```bash
# Verify MFA code
curl -X POST http://localhost:8080/api/auth/mfa/verify \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "code": "123456"
  }'
```

### Integration Flow

1. User attempts to login with email and password
2. If MFA is enabled, server returns `202 Accepted` with message indicating MFA is required
3. User receives 6-digit MFA code via email
4. User submits the MFA code using this endpoint
5. Server verifies the code and returns JWT tokens
6. User can now access protected resources using the JWT token

### Security Considerations

- MFA codes are single-use and expire after 10 minutes
- Failed verification attempts do not lock the account (only failed password attempts do)
- The code is securely stored in the database with an expiration timestamp
- Always use HTTPS in production to protect the MFA code in transit
