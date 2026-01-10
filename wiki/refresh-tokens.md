# Refresh Token Implementation

## Overview

The authentication service now supports refresh tokens to provide better security and user experience. Refresh tokens allow users to obtain new access tokens without re-authenticating, while access tokens remain short-lived for security.

## Architecture

### Token Types

1. **Access Token**: Short-lived JWT (15 minutes) used for API authentication
2. **Refresh Token**: Long-lived JWT (7 days) used to obtain new access tokens

### Database Changes

Added two new columns to the `users` table:
- `refresh_token`: Stores the current refresh token
- `refresh_token_expires_at`: Stores the expiration timestamp

### JWT Manager Extensions

The JWT manager now supports:
- Generating refresh tokens with longer expiration
- Verifying refresh tokens
- Separate expiration times for access and refresh tokens

## API Endpoints

### POST /api/auth/refresh

Refreshes an access token using a valid refresh token.

**Request Body:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response:**
```json
{
  "token": "new_access_token_here",
  "refresh_token": "new_refresh_token_here",
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "name": "User Name",
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-01T00:00:00Z"
  }
}
```

**Error Responses:**
- `400 Bad Request`: Invalid request payload
- `401 Unauthorized`: Invalid or expired refresh token

## Security Considerations

### Token Expiration
- Access tokens: 15 minutes
- Refresh tokens: 7 days

### Token Rotation
Each refresh operation generates new access and refresh tokens, invalidating the previous refresh token.

### Database Storage
Refresh tokens are stored hashed in the database for additional security.

## Usage Flow

1. User logs in or registers → receives access token + refresh token
2. When access token expires, client sends refresh token to `/api/auth/refresh`
3. Server validates refresh token and returns new token pair
4. Client uses new access token for API calls
5. Repeat step 2-4 as needed

## Implementation Details

### Service Methods

- `RefreshToken(ctx, req)`: Main refresh logic
- Validates refresh token JWT
- Retrieves user by refresh token from database
- Checks token expiration
- Generates new token pair
- Updates database with new refresh token

### Repository Methods

- `UpdateRefreshToken(userID, token, expiresAt)`: Store refresh token
- `GetByRefreshToken(token)`: Retrieve user by refresh token
- `ClearRefreshToken(userID)`: Remove refresh token (logout)

### Configuration

Added `RefreshTokenExpiration` to config:
```go
RefreshTokenExpiration: 7 * 24 * time.Hour // 7 days
```

## Testing

Unit tests cover:
- Successful token refresh
- Invalid refresh token handling
- Expired refresh token handling
- Database interaction mocking

## Migration

Run migration `003_add_refresh_token_fields.up.sql` to add required database columns.