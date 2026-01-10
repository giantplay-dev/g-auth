# Security Best Practices

## Table of Contents
- [Overview](#overview)
- [Authentication Security](#authentication-security)
- [Password Security](#password-security)
- [JWT Token Security](#jwt-token-security)
- [Database Security](#database-security)
- [API Security](#api-security)
- [Infrastructure Security](#infrastructure-security)
- [Security Checklist](#security-checklist)
- [Threat Model](#threat-model)
- [Incident Response](#incident-response)

---

## Overview

Security is paramount for an authentication service. This document outlines security best practices, potential vulnerabilities, and mitigation strategies for the g-auth service.

### Security Principles

1. **Defense in Depth**: Multiple layers of security
2. **Least Privilege**: Minimum necessary permissions
3. **Fail Secure**: Fail in a secure state
4. **Zero Trust**: Never trust, always verify
5. **Security by Design**: Security from the start

---

## Authentication Security

### Current Implementation

✅ **What We Have**:
- JWT-based authentication
- Password hashing with bcrypt
- Protected routes with middleware
- Request tracing for audit trails
- Structured logging

⚠️ **What's Missing**:
- Refresh token mechanism
- Token revocation/blacklist
- Multi-factor authentication (MFA)
- Session management
- Account lockout after failed attempts

### Recommendations

#### 1. Implement Refresh Tokens

**Problem**: Short-lived access tokens expire quickly, requiring frequent re-authentication.

**Solution**: Implement refresh token pattern:

```go
type TokenPair struct {
    AccessToken  string `json:"access_token"`   // Short-lived (15 min)
    RefreshToken string `json:"refresh_token"`  // Long-lived (7 days)
}

// Store refresh tokens in database with user_id, token_hash, expires_at
// On refresh: validate refresh token, issue new access token
// On logout: delete refresh token from database
```

**Benefits**:
- Better user experience (stay logged in)
- Improved security (short-lived access tokens)
- Ability to revoke sessions

#### 2. Token Blacklist for Logout

**Problem**: JWT tokens remain valid until expiration, even after logout.

**Solution**: Implement token blacklist using Redis:

```go
// On logout
func (s *AuthService) Logout(ctx context.Context, token string) error {
    // Extract expiration from token
    claims, _ := s.jwtManager.ValidateToken(token)
    
    // Store token in Redis until expiration
    ttl := time.Until(claims.ExpiresAt.Time)
    return s.redis.Set(ctx, "blacklist:"+token, "1", ttl).Err()
}

// In auth middleware
func AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        token := extractToken(r)
        
        // Check if token is blacklisted
        exists, _ := redis.Exists(ctx, "blacklist:"+token).Result()
        if exists > 0 {
            http.Error(w, "Token revoked", http.StatusUnauthorized)
            return
        }
        
        next.ServeHTTP(w, r)
    })
}
```

#### 3. Account Lockout

**Problem**: Brute force attacks on login endpoint.

**Solution**: Implement account lockout:

```go
// Track failed login attempts in Redis
const MaxFailedAttempts = 5
const LockoutDuration = 15 * time.Minute

func (s *AuthService) Login(ctx context.Context, req *domain.LoginRequest) (*domain.AuthResponse, error) {
    // Check if account is locked
    key := "login_attempts:" + req.Email
    attempts, _ := s.redis.Get(ctx, key).Int()
    
    if attempts >= MaxFailedAttempts {
        return nil, errors.New("account temporarily locked due to too many failed attempts")
    }
    
    // Attempt login
    user, err := s.userRepo.GetByEmail(ctx, req.Email)
    if err != nil || !password.Verify(user.Password, req.Password) {
        // Increment failed attempts
        s.redis.Incr(ctx, key)
        s.redis.Expire(ctx, key, LockoutDuration)
        return nil, domain.ErrInvalidCredentials
    }
    
    // Reset failed attempts on successful login
    s.redis.Del(ctx, key)
    
    // Generate token and return
    // ...
}
```

#### 4. Rate Limiting

**Problem**: API abuse and DDoS attacks.

**Solution**: Implement rate limiting per IP and per user:

```go
import "github.com/ulule/limiter/v3"

// Rate limit: 10 requests per minute for login
func RateLimitMiddleware(limiter *limiter.Limiter) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Get client IP
            ip := getClientIP(r)
            
            // Check rate limit
            context, err := limiter.Get(r.Context(), ip)
            if err != nil {
                http.Error(w, "Rate limit error", http.StatusInternalServerError)
                return
            }
            
            // Set rate limit headers
            w.Header().Set("X-RateLimit-Limit", strconv.FormatInt(context.Limit, 10))
            w.Header().Set("X-RateLimit-Remaining", strconv.FormatInt(context.Remaining, 10))
            w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(context.Reset, 10))
            
            if context.Reached {
                http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
                return
            }
            
            next.ServeHTTP(w, r)
        })
    }
}
```

**Recommended Limits**:
- Registration: 5 requests per hour per IP
- Login: 10 requests per 15 minutes per IP
- Protected endpoints: 100 requests per minute per user

---

## Password Security

### Current Implementation

✅ **Strong Password Hashing**:
- Algorithm: bcrypt
- Cost factor: 10 (2^10 = 1024 iterations)
- Salt: Automatically generated per password
- Timing-safe comparison

### Best Practices

#### 1. Password Requirements

Implement password validation:

```go
type PasswordRequirements struct {
    MinLength      int
    RequireUpper   bool
    RequireLower   bool
    RequireDigit   bool
    RequireSpecial bool
}

func ValidatePassword(password string, req PasswordRequirements) error {
    if len(password) < req.MinLength {
        return fmt.Errorf("password must be at least %d characters", req.MinLength)
    }
    
    if req.RequireUpper && !regexp.MustCompile(`[A-Z]`).MatchString(password) {
        return errors.New("password must contain at least one uppercase letter")
    }
    
    if req.RequireLower && !regexp.MustCompile(`[a-z]`).MatchString(password) {
        return errors.New("password must contain at least one lowercase letter")
    }
    
    if req.RequireDigit && !regexp.MustCompile(`[0-9]`).MatchString(password) {
        return errors.New("password must contain at least one digit")
    }
    
    if req.RequireSpecial && !regexp.MustCompile(`[!@#$%^&*(),.?":{}|<>]`).MatchString(password) {
        return errors.New("password must contain at least one special character")
    }
    
    return nil
}
```

**Recommended Requirements**:
- Minimum 8 characters (12+ recommended)
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character
- Not in common password list

#### 2. Prevent Common Passwords

```go
// Check against common password list
var commonPasswords = []string{
    "password", "123456", "password123", "admin", "letmein",
    // ... (load from file or database)
}

func IsCommonPassword(password string) bool {
    lower := strings.ToLower(password)
    for _, common := range commonPasswords {
        if lower == common {
            return true
        }
    }
    return false
}
```

#### 3. Password Reset Security

```go
// Secure password reset flow
type PasswordResetToken struct {
    Token     string
    UserID    uuid.UUID
    ExpiresAt time.Time
}

// Generate secure random token
func GenerateResetToken() (string, error) {
    bytes := make([]byte, 32)
    if _, err := rand.Read(bytes); err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(bytes), nil
}

// Send reset email (use email service)
func SendPasswordResetEmail(email, token string) error {
    resetLink := fmt.Sprintf("https://yourapp.com/reset-password?token=%s", token)
    // Send email with reset link
    // Token should expire in 1 hour
}
```

---

## JWT Token Security

### Current Implementation

✅ **JWT Configuration**:
- Algorithm: HS256 (HMAC with SHA-256)
- Expiration: 1 minute (configurable)
- Claims: user_id, exp

### Security Recommendations

#### 1. Token Expiration

**Current**: 1 minute (too short for production)

**Recommended**:
- Access tokens: 15 minutes
- Refresh tokens: 7 days
- Remember me tokens: 30 days

```go
type JWTManager struct {
    secret              []byte
    accessTokenExpiry   time.Duration // 15 minutes
    refreshTokenExpiry  time.Duration // 7 days
}
```

#### 2. Token Claims

Add more security claims:

```go
type TokenClaims struct {
    UserID    uuid.UUID `json:"user_id"`
    Email     string    `json:"email"`
    TokenType string    `json:"token_type"` // "access" or "refresh"
    IssuedAt  int64     `json:"iat"`
    ExpiresAt int64     `json:"exp"`
    NotBefore int64     `json:"nbf"`
    JTI       string    `json:"jti"` // JWT ID for revocation
}
```

#### 3. JWT Secret Management

**Current**: Environment variable

**Recommended**:
- Use secrets management service (AWS Secrets Manager, HashiCorp Vault)
- Rotate secrets regularly
- Use different secrets for different environments
- Use asymmetric keys (RS256) for better security

```go
// RS256 (asymmetric) is more secure than HS256
// Private key for signing, public key for verification
func NewRSAJWTManager(privateKeyPath, publicKeyPath string) (*JWTManager, error) {
    privateKey, err := loadPrivateKey(privateKeyPath)
    if err != nil {
        return nil, err
    }
    
    publicKey, err := loadPublicKey(publicKeyPath)
    if err != nil {
        return nil, err
    }
    
    return &JWTManager{
        privateKey: privateKey,
        publicKey:  publicKey,
    }, nil
}
```

#### 4. Token Storage (Client-Side)

**Best Practices for Clients**:

❌ **Don't Store In**:
- LocalStorage (vulnerable to XSS)
- SessionStorage (vulnerable to XSS)
- Plain cookies (vulnerable to CSRF)

✅ **Do Store In**:
- HttpOnly cookies (prevents XSS access)
- Secure cookies (HTTPS only)
- SameSite cookies (prevents CSRF)

```go
// Set cookie in handler
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
    // ... authenticate user ...
    
    // Set HttpOnly cookie
    http.SetCookie(w, &http.Cookie{
        Name:     "access_token",
        Value:    token,
        Path:     "/",
        HttpOnly: true,  // Prevents JavaScript access
        Secure:   true,  // HTTPS only
        SameSite: http.SameSiteStrictMode, // CSRF protection
        MaxAge:   900,   // 15 minutes
    })
}
```

---

## Database Security

### Current Implementation

✅ **Security Measures**:
- Parameterized queries (prevents SQL injection)
- Password field excluded from JSON responses
- Connection pooling

### Recommendations

#### 1. SSL/TLS Connections

Always use SSL in production:

```bash
# Connection string with SSL
DATABASE_URL=postgres://user:pass@host:5432/db?sslmode=require

# Verify server certificate
DATABASE_URL=postgres://user:pass@host:5432/db?sslmode=verify-full&sslrootcert=/path/to/ca.crt
```

#### 2. Database User Permissions

**Principle of Least Privilege**:

```sql
-- Create dedicated database user for application
CREATE USER authservice WITH PASSWORD 'strong-password';

-- Grant only necessary permissions
GRANT CONNECT ON DATABASE authdb TO authservice;
GRANT SELECT, INSERT, UPDATE ON users TO authservice;
GRANT USAGE, SELECT ON SEQUENCE users_id_seq TO authservice;

-- Revoke unnecessary permissions
REVOKE CREATE ON SCHEMA public FROM authservice;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
```

#### 3. Database Encryption

- **At Rest**: Enable PostgreSQL encryption
- **In Transit**: Use SSL/TLS connections
- **Column-Level**: Encrypt sensitive data (PII)

```sql
-- Enable pgcrypto extension for encryption
CREATE EXTENSION pgcrypto;

-- Encrypt sensitive data
INSERT INTO users (email, encrypted_data)
VALUES ('user@example.com', pgp_sym_encrypt('sensitive data', 'encryption-key'));

-- Decrypt when querying
SELECT email, pgp_sym_decrypt(encrypted_data, 'encryption-key')
FROM users;
```

#### 4. Database Audit Logging

Enable PostgreSQL audit logging:

```sql
-- Log all DDL and DML statements
ALTER SYSTEM SET log_statement = 'all';

-- Log connection attempts
ALTER SYSTEM SET log_connections = on;
ALTER SYSTEM SET log_disconnections = on;

-- Reload configuration
SELECT pg_reload_conf();
```

#### 5. Backup Encryption

Encrypt database backups:

```bash
# Encrypted backup
pg_dump $DATABASE_URL | gpg --encrypt --recipient admin@example.com > backup.sql.gpg

# Encrypted restore
gpg --decrypt backup.sql.gpg | psql $DATABASE_URL
```

---

## API Security

### 1. Input Validation

**Always validate and sanitize input**:

```go
func ValidateEmail(email string) error {
    if len(email) == 0 {
        return errors.New("email is required")
    }
    
    if len(email) > 255 {
        return errors.New("email too long")
    }
    
    emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
    if !emailRegex.MatchString(email) {
        return errors.New("invalid email format")
    }
    
    return nil
}

func ValidateName(name string) error {
    if len(name) == 0 {
        return errors.New("name is required")
    }
    
    if len(name) > 255 {
        return errors.New("name too long")
    }
    
    // Allow only letters, spaces, hyphens, apostrophes
    nameRegex := regexp.MustCompile(`^[a-zA-Z\s'-]+$`)
    if !nameRegex.MatchString(name) {
        return errors.New("name contains invalid characters")
    }
    
    return nil
}
```

### 2. CORS Configuration

**Secure CORS settings**:

```go
import "github.com/rs/cors"

func setupCORS() *cors.Cors {
    return cors.New(cors.Options{
        AllowedOrigins: []string{
            "https://yourapp.com",
            "https://www.yourapp.com",
        },
        AllowedMethods: []string{
            http.MethodGet,
            http.MethodPost,
            http.MethodPut,
            http.MethodDelete,
            http.MethodOptions,
        },
        AllowedHeaders: []string{
            "Content-Type",
            "Authorization",
        },
        AllowCredentials: true,
        MaxAge:           300, // 5 minutes
    })
}
```

**DO NOT** use wildcard (`*`) in production!

### 3. Request Size Limits

Prevent large payloads:

```go
func RequestSizeLimitMiddleware(maxSize int64) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            r.Body = http.MaxBytesReader(w, r.Body, maxSize)
            next.ServeHTTP(w, r)
        })
    }
}

// Usage: Limit to 1MB
router.Use(RequestSizeLimitMiddleware(1 << 20))
```

### 4. Security Headers

Add security headers:

```go
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Prevent clickjacking
        w.Header().Set("X-Frame-Options", "DENY")
        
        // Prevent MIME type sniffing
        w.Header().Set("X-Content-Type-Options", "nosniff")
        
        // Enable XSS protection
        w.Header().Set("X-XSS-Protection", "1; mode=block")
        
        // Content Security Policy
        w.Header().Set("Content-Security-Policy", "default-src 'self'")
        
        // Referrer Policy
        w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
        
        // HSTS (if using HTTPS)
        w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        
        next.ServeHTTP(w, r)
    })
}
```

---

## Infrastructure Security

### 1. HTTPS/TLS

**Always use HTTPS in production**:

```go
// Redirect HTTP to HTTPS
func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
    target := "https://" + r.Host + r.URL.Path
    http.Redirect(w, r, target, http.StatusMovedPermanently)
}

// Serve with TLS
func main() {
    // ... setup ...
    
    // HTTP server (redirect to HTTPS)
    go http.ListenAndServe(":80", http.HandlerFunc(redirectToHTTPS))
    
    // HTTPS server
    log.Fatal(server.ListenAndServeTLS("cert.pem", "key.pem"))
}
```

### 2. Firewall Rules

**Network Security**:

```bash
# Allow only necessary ports
# SSH: 22 (restricted IPs)
# HTTP: 80 (redirect to HTTPS)
# HTTPS: 443
# PostgreSQL: 5432 (internal only)

# Example: AWS Security Group
# Inbound Rules:
# - Port 80 (HTTP) from 0.0.0.0/0
# - Port 443 (HTTPS) from 0.0.0.0/0
# - Port 22 (SSH) from your-ip/32
# - Port 5432 (PostgreSQL) from app-security-group only

# Outbound Rules:
# - All traffic (or restrict to necessary destinations)
```

### 3. Secrets Management

**Never hardcode secrets**:

```go
// Use AWS Secrets Manager
import "github.com/aws/aws-sdk-go/service/secretsmanager"

func loadSecretsFromAWS(secretName string) (*Config, error) {
    svc := secretsmanager.New(session.New())
    input := &secretsmanager.GetSecretValueInput{
        SecretId: aws.String(secretName),
    }
    
    result, err := svc.GetSecretValue(input)
    if err != nil {
        return nil, err
    }
    
    var config Config
    json.Unmarshal([]byte(*result.SecretString), &config)
    return &config, nil
}
```

### 4. Container Security

**Docker best practices**:

```dockerfile
# Use minimal base image
FROM alpine:latest

# Don't run as root
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# Copy only necessary files
COPY --chown=appuser:appgroup ./auth-service /app/

# Set read-only filesystem (if possible)
# Add in docker-compose or k8s
# read_only: true
```

---

## Security Checklist

### Development

- [ ] All inputs validated and sanitized
- [ ] No secrets in code or version control
- [ ] Dependencies regularly updated
- [ ] Code reviews include security review
- [ ] Automated security scans (SAST, DAST)
- [ ] Unit tests include security test cases

### Deployment

- [ ] HTTPS/TLS enabled
- [ ] Database SSL connections enabled
- [ ] Firewall rules configured
- [ ] Rate limiting enabled
- [ ] Security headers added
- [ ] CORS properly configured
- [ ] Secrets in secure storage (not .env files)
- [ ] Container images scanned for vulnerabilities

### Monitoring

- [ ] Failed login attempts monitored
- [ ] Suspicious activity alerts configured
- [ ] Log aggregation set up
- [ ] Error tracking enabled (e.g., Sentry)
- [ ] Performance monitoring (APM)
- [ ] Database query monitoring

### Compliance

- [ ] GDPR compliance (if applicable)
- [ ] Data retention policy defined
- [ ] Privacy policy published
- [ ] Terms of service published
- [ ] Data breach response plan documented

---

## Threat Model

### Common Threats

| Threat | Risk | Mitigation |
|--------|------|------------|
| SQL Injection | High | Parameterized queries ✅ |
| XSS | Medium | Input sanitization, CSP headers |
| CSRF | Medium | SameSite cookies, CSRF tokens |
| Brute Force | High | Rate limiting, account lockout |
| Token Theft | High | Short-lived tokens, HTTPS only |
| Password Leaks | High | Strong hashing (bcrypt) ✅ |
| DDoS | High | Rate limiting, CDN, WAF |
| MITM | High | HTTPS/TLS ✅ |
| Session Hijacking | Medium | Secure cookies, token rotation |
| Privilege Escalation | Medium | RBAC, principle of least privilege |

---

## Incident Response

### Security Incident Plan

1. **Detection**: Monitor for security events
2. **Containment**: Isolate affected systems
3. **Investigation**: Determine scope and impact
4. **Eradication**: Remove threat
5. **Recovery**: Restore normal operations
6. **Post-Incident**: Document lessons learned

### Example: Suspected Token Compromise

```
1. Detection: Unusual activity detected for user
2. Immediate Actions:
   - Revoke all tokens for user
   - Force password reset
   - Lock account temporarily
3. Investigation:
   - Review access logs
   - Check for unauthorized access
   - Identify affected data
4. Communication:
   - Notify user
   - Document incident
5. Prevention:
   - Update security measures
   - Implement additional monitoring
```

---

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)

---

**Last Updated**: January 10, 2026
