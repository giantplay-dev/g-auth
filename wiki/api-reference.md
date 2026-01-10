# API Reference

## Base Information

- **Base URL**: `http://localhost:8080`
- **API Version**: v1
- **Authentication**: JWT Bearer Token
- **Content-Type**: `application/json`

## Authentication

Protected endpoints require a JWT token in the Authorization header:

```
Authorization: Bearer <jwt-token>
```

## Error Response Format

All error responses follow this format:

```json
{
  "error": "Error message describing what went wrong"
}
```

## Status Codes

| Code | Meaning |
|------|---------|
| 200  | OK - Request succeeded |
| 201  | Created - Resource created successfully |
| 400  | Bad Request - Invalid request format |
| 401  | Unauthorized - Missing or invalid authentication |
| 404  | Not Found - Resource not found |
| 409  | Conflict - Resource already exists |
| 500  | Internal Server Error - Server error |

---

## Endpoints

### 1. Health Check

Check if the service is running.

**Endpoint**: `GET /health`

**Authentication**: None required

**Request**:
```http
GET /health HTTP/1.1
Host: localhost:8080
```

**Response**:
```json
{
  "status": "ok"
}
```

**Status Codes**:
- `200 OK`: Service is healthy

---

### 2. Register User

Create a new user account.

**Endpoint**: `POST /api/auth/register`

**Authentication**: None required

**Request Headers**:
```
Content-Type: application/json
```

**Request Body**:
```json
{
  "email": "user@example.com",
  "password": "SecureP@ssw0rd",
  "name": "John Doe"
}
```

**Request Fields**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| email | string | Yes | User's email address (must be unique) |
| password | string | Yes | User's password (min 8 characters recommended) |
| name | string | Yes | User's full name |

**Success Response** (201 Created):
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMTIzZTQ1NjctZTg5Yi0xMmQzLWE0NTYtNDI2NjE0MTc0MDAwIiwiZXhwIjoxNzM2NTA1NjAwfQ.abc123...",
  "user": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "email": "user@example.com",
    "name": "John Doe",
    "created_at": "2026-01-10T10:00:00Z",
    "updated_at": "2026-01-10T10:00:00Z"
  }
}
```

**Response Fields**:

| Field | Type | Description |
|-------|------|-------------|
| token | string | JWT authentication token |
| user.id | string (UUID) | Unique user identifier |
| user.email | string | User's email address |
| user.name | string | User's full name |
| user.created_at | string (ISO 8601) | Account creation timestamp |
| user.updated_at | string (ISO 8601) | Last update timestamp |

**Error Responses**:

**400 Bad Request** - Invalid request format:
```json
{
  "error": "Invalid request payload"
}
```

**409 Conflict** - Email already exists:
```json
{
  "error": "user already exists"
}
```

**500 Internal Server Error** - Server error:
```json
{
  "error": "Failed to register user"
}
```

**Example Request**:

```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com",
    "password": "MySecurePassword123!",
    "name": "John Doe"
  }'
```

**Example Response**:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "email": "john.doe@example.com",
    "name": "John Doe",
    "created_at": "2026-01-10T15:30:00Z",
    "updated_at": "2026-01-10T15:30:00Z"
  }
}
```

---

### 3. Login

Authenticate a user and receive a JWT token.

**Endpoint**: `POST /api/auth/login`

**Authentication**: None required

**Request Headers**:
```
Content-Type: application/json
```

**Request Body**:
```json
{
  "email": "user@example.com",
  "password": "SecureP@ssw0rd"
}
```

**Request Fields**:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| email | string | Yes | User's registered email address |
| password | string | Yes | User's password |

**Success Response** (200 OK):
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMTIzZTQ1NjctZTg5Yi0xMmQzLWE0NTYtNDI2NjE0MTc0MDAwIiwiZXhwIjoxNzM2NTA1NjAwfQ.abc123...",
  "user": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "email": "user@example.com",
    "name": "John Doe",
    "created_at": "2026-01-10T10:00:00Z",
    "updated_at": "2026-01-10T10:00:00Z"
  }
}
```

**Error Responses**:

**400 Bad Request** - Invalid request format:
```json
{
  "error": "Invalid request payload"
}
```

**401 Unauthorized** - Invalid credentials:
```json
{
  "error": "invalid credentials"
}
```

**500 Internal Server Error** - Server error:
```json
{
  "error": "Failed to login"
}
```

**Example Request**:

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com",
    "password": "MySecurePassword123!"
  }'
```

**Example Response**:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "email": "john.doe@example.com",
    "name": "John Doe",
    "created_at": "2026-01-10T15:30:00Z",
    "updated_at": "2026-01-10T15:30:00Z"
  }
}
```

---

### 4. Get Current User

Get the authenticated user's profile.

**Endpoint**: `GET /api/me`

**Authentication**: Required (JWT Token)

**Request Headers**:
```
Authorization: Bearer <jwt-token>
```

**Request Body**: None

**Success Response** (200 OK):
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "email": "user@example.com",
  "name": "John Doe",
  "created_at": "2026-01-10T10:00:00Z",
  "updated_at": "2026-01-10T10:00:00Z"
}
```

**Response Fields**:

| Field | Type | Description |
|-------|------|-------------|
| id | string (UUID) | Unique user identifier |
| email | string | User's email address |
| name | string | User's full name |
| created_at | string (ISO 8601) | Account creation timestamp |
| updated_at | string (ISO 8601) | Last update timestamp |

**Note**: The `password` field is never returned in any response.

**Error Responses**:

**401 Unauthorized** - Missing or invalid token:
```json
{
  "error": "missing or invalid authorization header"
}
```

**401 Unauthorized** - Invalid token:
```json
{
  "error": "invalid token"
}
```

**404 Not Found** - User not found:
```json
{
  "error": "User not found"
}
```

**Example Request**:

```bash
curl -X GET http://localhost:8080/api/me \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Example Response**:
```json
{
  "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "email": "john.doe@example.com",
  "name": "John Doe",
  "created_at": "2026-01-10T15:30:00Z",
  "updated_at": "2026-01-10T15:30:00Z"
}
```

---

## JWT Token Structure

The JWT token consists of three parts separated by dots:

```
header.payload.signature
```

### Header
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

### Payload (Claims)
```json
{
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "exp": 1736505600
}
```

### Token Expiration

- **Default Expiration**: 1 minute (configurable via `JWT_EXPIRATION`)
- **Expiration Field**: `exp` (Unix timestamp)
- **After Expiration**: Token becomes invalid and returns 401 Unauthorized

---

## Request Tracing

Every request is assigned a unique trace ID for debugging and monitoring purposes. The trace ID is:

1. Generated by the tracing middleware
2. Added to request context
3. Included in all log entries
4. Can be used to correlate logs across services

**Trace ID Format**: UUID v4

---

## Rate Limiting

**Current Status**: Not implemented

**Recommended Implementation**:
- Rate limit by IP address
- Rate limit by user ID (for authenticated requests)
- Different limits for public vs authenticated endpoints
- Recommended limits:
  - Registration: 5 requests per hour per IP
  - Login: 10 requests per 15 minutes per IP
  - Protected endpoints: 100 requests per minute per user

---

## CORS Configuration

**Current Status**: Not configured

**Recommended Configuration**:
```go
// Allow specific origins in production
AllowedOrigins: []string{"https://yourdomain.com"}
AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
AllowedHeaders: []string{"Content-Type", "Authorization"}
AllowCredentials: true
MaxAge: 300
```

---

## Authentication Flow

### Registration Flow

```
1. POST /api/auth/register
   ├── Server validates request format
   ├── Server checks if email already exists
   ├── Server hashes password with bcrypt
   ├── Server creates user in database
   ├── Server generates JWT token
   └── Server returns token + user data

2. Client stores JWT token
3. Client includes token in subsequent requests
```

### Login Flow

```
1. POST /api/auth/login
   ├── Server validates request format
   ├── Server fetches user by email
   ├── Server verifies password with bcrypt
   ├── Server generates JWT token
   └── Server returns token + user data

2. Client stores JWT token
3. Client includes token in subsequent requests
```

### Protected Route Access

```
1. Client sends request with Authorization header
   └── Authorization: Bearer <token>

2. Auth middleware validates token
   ├── Extracts token from header
   ├── Verifies token signature
   ├── Checks expiration
   ├── Extracts user_id from claims
   └── Adds user_id to request context

3. Handler processes request
   ├── Retrieves user_id from context
   ├── Performs business logic
   └── Returns response
```

---

## Best Practices

### For API Consumers

1. **Store Tokens Securely**
   - Use httpOnly cookies or secure storage
   - Never store in localStorage for sensitive apps
   - Clear tokens on logout

2. **Handle Token Expiration**
   - Implement token refresh logic
   - Handle 401 responses gracefully
   - Redirect to login when token expires

3. **Include Proper Headers**
   - Always set `Content-Type: application/json`
   - Include `Authorization` header for protected routes

4. **Error Handling**
   - Check response status codes
   - Parse error messages
   - Show user-friendly error messages

### For API Maintainers

1. **Never Log Passwords**
   - Sanitize logs
   - Mask sensitive data

2. **Use HTTPS in Production**
   - Never send tokens over HTTP
   - Configure TLS properly

3. **Validate Input**
   - Email format validation
   - Password strength requirements
   - Request size limits

4. **Monitor API Usage**
   - Track failed login attempts
   - Monitor for suspicious patterns
   - Set up alerts for anomalies

---

## Examples with Different Languages

### JavaScript (Fetch API)

```javascript
// Register
const register = async (email, password, name) => {
  const response = await fetch('http://localhost:8080/api/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password, name })
  });
  return await response.json();
};

// Login
const login = async (email, password) => {
  const response = await fetch('http://localhost:8080/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  return await response.json();
};

// Get current user
const getCurrentUser = async (token) => {
  const response = await fetch('http://localhost:8080/api/me', {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  return await response.json();
};
```

### Python (Requests)

```python
import requests

# Register
def register(email, password, name):
    url = 'http://localhost:8080/api/auth/register'
    data = {'email': email, 'password': password, 'name': name}
    response = requests.post(url, json=data)
    return response.json()

# Login
def login(email, password):
    url = 'http://localhost:8080/api/auth/login'
    data = {'email': email, 'password': password}
    response = requests.post(url, json=data)
    return response.json()

# Get current user
def get_current_user(token):
    url = 'http://localhost:8080/api/me'
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(url, headers=headers)
    return response.json()
```

### Go (net/http)

```go
import (
    "bytes"
    "encoding/json"
    "net/http"
)

// Register
func register(email, password, name string) (map[string]interface{}, error) {
    url := "http://localhost:8080/api/auth/register"
    body := map[string]string{"email": email, "password": password, "name": name}
    jsonBody, _ := json.Marshal(body)
    
    resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonBody))
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var result map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&result)
    return result, nil
}

// Login
func login(email, password string) (map[string]interface{}, error) {
    url := "http://localhost:8080/api/auth/login"
    body := map[string]string{"email": email, "password": password}
    jsonBody, _ := json.Marshal(body)
    
    resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonBody))
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var result map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&result)
    return result, nil
}

// Get current user
func getCurrentUser(token string) (map[string]interface{}, error) {
    url := "http://localhost:8080/api/me"
    req, _ := http.NewRequest("GET", url, nil)
    req.Header.Set("Authorization", "Bearer "+token)
    
    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var result map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&result)
    return result, nil
}
```

---

**Last Updated**: January 10, 2026
