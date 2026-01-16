# Multi-Factor Authentication (MFA)

## Overview

The G-Auth service implements email-based Multi-Factor Authentication (MFA) to provide an additional layer of security for user accounts. When MFA is enabled, users must verify their identity by entering a code sent to their email address after successfully entering their credentials.

## How It Works

### Authentication Flow with MFA

1. **User Login**: User submits email and password
2. **Credential Verification**: System verifies email and password
3. **MFA Check**: If MFA is enabled for the user:
   - System generates a 6-digit code
   - Code is sent to user's email
   - System returns HTTP 202 with "MFA required" message
4. **Code Verification**: User submits the code from email
5. **Token Generation**: System validates code and returns JWT tokens

### MFA Code Properties

- **Format**: 6-digit numeric code (000000 - 999999)
- **Validity**: 10 minutes from generation
- **Single-use**: Code is cleared after successful verification
- **Delivery**: Sent via email to user's registered email address

## API Endpoints

### Public Endpoints

- `POST /api/auth/mfa/verify` - Verify MFA code after login

### Protected Endpoints (Require Authentication)

- `POST /api/mfa/enable` - Enable MFA for the authenticated user
- `POST /api/mfa/disable` - Disable MFA for the authenticated user
- `GET /api/mfa/status` - Get current MFA status

## Database Schema

The MFA feature adds the following fields to the `users` table:

```sql
mfa_enabled BOOLEAN DEFAULT FALSE NOT NULL
mfa_code VARCHAR(6)
mfa_code_expires_at TIMESTAMP
```

An index is created on `mfa_code` for efficient lookups:

```sql
CREATE INDEX idx_users_mfa_code ON users(mfa_code) WHERE mfa_code IS NOT NULL;
```

## Enabling MFA

### Requirements

- User must be authenticated
- User must provide their current password

### Process

1. User calls `POST /api/mfa/enable` with their password
2. System verifies the password
3. System sets `mfa_enabled = true` for the user
4. Future logins will require MFA verification

### Example

```bash
curl -X POST http://localhost:8080/api/mfa/enable \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <jwt_token>" \
  -d '{"password": "MySecurePassword123!"}'
```

## Disabling MFA

### Requirements

- User must be authenticated
- User must provide their current password

### Process

1. User calls `POST /api/mfa/disable` with their password
2. System verifies the password
3. System sets `mfa_enabled = false` and clears any pending MFA codes
4. Future logins will not require MFA verification

### Example

```bash
curl -X POST http://localhost:8080/api/mfa/disable \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <jwt_token>" \
  -d '{"password": "MySecurePassword123!"}'
```

## Login Flow with MFA

### Without MFA

```
POST /api/auth/login
→ Verify credentials
→ Return JWT tokens (200 OK)
```

### With MFA

```
POST /api/auth/login
→ Verify credentials
→ Generate and send MFA code
→ Return "MFA required" message (202 Accepted)

POST /api/auth/mfa/verify
→ Verify MFA code
→ Return JWT tokens (200 OK)
```

## Email Template

When a user logs in with MFA enabled, they receive an email with the following information:

- **Subject**: "Your Multi-Factor Authentication Code"
- **Code**: 6-digit numeric code prominently displayed
- **Validity**: "This code will expire in 10 minutes"
- **Security Note**: Instructions to ignore if not requested

## Security Considerations

### Code Generation

- Uses cryptographically secure random number generation (`crypto/rand`)
- 6-digit codes provide 1,000,000 possible combinations
- Short validity period (10 minutes) limits attack window

### Password Verification

- Enabling/disabling MFA requires password confirmation
- Prevents unauthorized changes if session is compromised

### Failed Attempts

- MFA verification failures do NOT trigger account lockout
- Only password authentication failures trigger lockout
- Prevents denial-of-service via MFA attempts

### Code Storage

- Codes are hashed before storage (currently stored as plaintext - consider hashing in production)
- Codes are cleared after successful verification
- Expired codes are automatically invalidated

### Email Security

- Users should be advised to keep their email account secure
- Email should use strong passwords and MFA (if available)
- Consider implementing backup codes for account recovery

## Error Handling

### Common Errors

| Error | HTTP Code | Description |
|-------|-----------|-------------|
| `ErrMFARequired` | 202 | MFA verification required |
| `ErrInvalidMFACode` | 401 | Code doesn't match |
| `ErrMFACodeExpired` | 401 | Code has expired |
| `ErrMFAAlreadyEnabled` | 400 | MFA is already active |
| `ErrMFANotEnabled` | 400 | MFA is not active |

## Testing

### Unit Tests

- `pkg/mfa/mfa_test.go` - Tests for code generation and validation
- Run with: `go test ./pkg/mfa/`

### Manual Testing

1. **Enable MFA**:
   ```bash
   # Register and login
   TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email":"test@example.com","password":"password"}' \
     | jq -r .token)
   
   # Enable MFA
   curl -X POST http://localhost:8080/api/mfa/enable \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"password":"password"}'
   ```

2. **Test Login with MFA**:
   ```bash
   # Login - should return 202 with MFA required
   curl -X POST http://localhost:8080/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email":"test@example.com","password":"password"}'
   
   # Check email for code and verify
   curl -X POST http://localhost:8080/api/auth/mfa/verify \
     -H "Content-Type: application/json" \
     -d '{"email":"test@example.com","code":"123456"}'
   ```

## Migration

To add MFA support to an existing database:

```bash
make migrate-006-up
```

To rollback:

```bash
make migrate-006-down
```

## Future Enhancements

- **SMS-based MFA**: Support for SMS delivery in addition to email
- **TOTP (Time-based One-Time Password)**: Support for authenticator apps like Google Authenticator
- **Backup Codes**: Generate one-time recovery codes for account access
- **Trusted Devices**: Remember devices to skip MFA for a period
- **MFA Enforcement**: Allow administrators to enforce MFA for all users
- **Code Hashing**: Hash MFA codes before storing in database
- **Audit Logging**: Log all MFA-related events for security monitoring

## Best Practices

1. **User Communication**: Clearly explain MFA benefits to users
2. **Gradual Rollout**: Consider making MFA optional initially
3. **Recovery Process**: Document clear steps for users locked out of email
4. **Email Provider**: Ensure reliable email delivery with proper SMTP configuration
5. **Rate Limiting**: Already implemented at API level to prevent abuse
6. **HTTPS Only**: Always use HTTPS in production to protect codes in transit

## Troubleshooting

### MFA Code Not Received

1. Check spam/junk folder
2. Verify SMTP configuration in `.env`
3. Check application logs for email sending errors
4. Verify email address is correct in user profile

### Code Expired

- MFA codes expire after 10 minutes
- Users can attempt login again to receive a new code

### MFA Cannot Be Disabled

- Ensure password is correct
- Verify JWT token is valid
- Check that MFA is actually enabled for the user

## Configuration

Environment variables related to MFA:

```env
# SMTP Configuration (for sending MFA codes)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=your-email@gmail.com
```

## API Documentation

For detailed API documentation, see:

- [MFA Verification](./api-docs/mfa-verify.md)
- [Enable MFA](./api-docs/mfa-enable.md)
- [Disable MFA](./api-docs/mfa-disable.md)
- [MFA Status](./api-docs/mfa-status.md)
