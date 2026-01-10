# Troubleshooting Guide

## Table of Contents
- [Common Issues](#common-issues)
- [Database Issues](#database-issues)
- [Authentication Issues](#authentication-issues)
- [Network Issues](#network-issues)
- [Performance Issues](#performance-issues)
- [Logging and Debugging](#logging-and-debugging)
- [FAQ](#faq)

---

## Common Issues

### Service Won't Start

#### Symptom
Server fails to start or exits immediately

#### Common Causes

**1. Port Already in Use**

```bash
# Error message
panic: listen tcp :8080: bind: address already in use

# Solution: Find and kill process using port
lsof -i :8080
kill -9 <PID>

# Or use a different port
PORT=8081 go run cmd/server/main.go
```

**2. Database Connection Failure**

```bash
# Error message
Failed to connect to database: dial tcp: lookup postgres: no such host

# Solution: Check DATABASE_URL
echo $DATABASE_URL

# Verify database is running
pg_isready -h localhost -p 5432

# Test connection
psql $DATABASE_URL -c "SELECT 1;"
```

**3. Missing Environment Variables**

```bash
# Error message
JWT_SECRET environment variable not set

# Solution: Create .env file
cat > .env << EOF
ENV=development
PORT=8080
DATABASE_URL=postgres://postgres:postgres@localhost:5432/authdb?sslmode=disable
JWT_SECRET=your-secret-key-here
EOF

# Or export variables
export JWT_SECRET="your-secret-key-here"
```

**4. Migration Not Run**

```bash
# Error message
ERROR: relation "users" does not exist

# Solution: Run migrations
make migrate-up

# Or manually
psql $DATABASE_URL -f migrations/001_create_users_table.up.sql
```

---

## Database Issues

### Cannot Connect to Database

#### Issue: Connection Refused

```bash
# Error
dial tcp [::1]:5432: connect: connection refused

# Check if PostgreSQL is running
sudo systemctl status postgresql

# Start PostgreSQL
sudo systemctl start postgresql

# For Docker
docker ps -a | grep postgres
docker start auth-postgres
```

#### Issue: Authentication Failed

```bash
# Error
pq: password authentication failed for user "authuser"

# Solution: Check credentials in DATABASE_URL
# Format: postgres://username:password@host:port/database

# Reset password (as postgres superuser)
psql -U postgres -c "ALTER USER authuser PASSWORD 'newpassword';"
```

#### Issue: Database Does Not Exist

```bash
# Error
pq: database "authdb" does not exist

# Solution: Create database
psql -U postgres -c "CREATE DATABASE authdb;"

# Or with Docker
docker exec -it auth-postgres psql -U postgres -c "CREATE DATABASE authdb;"
```

### Connection Pool Exhausted

```bash
# Error
pq: sorry, too many clients already

# Solution 1: Increase max_connections in PostgreSQL
# Edit postgresql.conf
max_connections = 200

# Solution 2: Configure connection pool in application
db.SetMaxOpenConns(25)
db.SetMaxIdleConns(5)
db.SetConnMaxLifetime(5 * time.Minute)
```

### Migration Errors

#### Migration Already Applied

```bash
# Error
ERROR: relation "users" already exists

# Solution: Skip migration or run down migration first
make migrate-down
make migrate-up
```

#### Migration Partially Applied

```bash
# Solution: Manually check and fix
psql $DATABASE_URL

# Check what exists
\dt

# If table exists but indexes don't, recreate them
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
```

---

## Authentication Issues

### JWT Token Invalid

#### Issue: Token Always Returns 401

```bash
# Possible causes:
1. JWT_SECRET mismatch between token generation and validation
2. Token expired
3. Malformed token
4. Wrong Authorization header format

# Debugging steps:

# 1. Check JWT_SECRET is set consistently
echo $JWT_SECRET

# 2. Decode JWT token to inspect claims
# Use https://jwt.io or
go run -c '
package main
import (
    "encoding/json"
    "fmt"
    "encoding/base64"
    "strings"
)
func main() {
    token := "your.jwt.token"
    parts := strings.Split(token, ".")
    payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
    var claims map[string]interface{}
    json.Unmarshal(payload, &claims)
    fmt.Println(claims)
}
'

# 3. Check token expiration
# Default expiration is 1 minute - very short!
# Increase JWT_EXPIRATION in config

# 4. Verify Authorization header format
# Correct: Authorization: Bearer <token>
# Incorrect: Authorization: <token>
```

#### Issue: Token Expires Too Quickly

```bash
# Default expiration: 1 minute

# Solution: Update config.go
JWTExpiration: 15 * time.Minute,  // Change from 1 to 15 minutes

# Or set via environment
export JWT_EXPIRATION=900  # 15 minutes in seconds
```

### Login Fails with Valid Credentials

#### Issue: Invalid Credentials Error

```bash
# Possible causes:
1. Password not hashed correctly during registration
2. Password comparison failing
3. User not in database

# Debug steps:

# 1. Check if user exists
psql $DATABASE_URL -c "SELECT id, email, name FROM users WHERE email='user@example.com';"

# 2. Check password hash exists (don't display it!)
psql $DATABASE_URL -c "SELECT LENGTH(password) FROM users WHERE email='user@example.com';"
# Should return 60 (bcrypt hash length)

# 3. Test password verification
# Add debug logging in service/auth_service.go
log.Printf("Password verification result: %v", password.Verify(user.Password, req.Password))

# 4. Register new user and test
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"TestPassword123","name":"Test User"}'
```

### Cannot Register User

#### Issue: Email Already Exists

```bash
# Error
{"error":"user already exists"}

# Solution: Use different email or delete existing user
psql $DATABASE_URL -c "DELETE FROM users WHERE email='user@example.com';"
```

#### Issue: Invalid Request Payload

```bash
# Error
{"error":"Invalid request payload"}

# Common causes:
1. Malformed JSON
2. Missing required fields
3. Wrong Content-Type header

# Correct request:
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123",
    "name": "John Doe"
  }'

# Test JSON validity
echo '{"email":"test@example.com"}' | jq .
```

---

## Network Issues

### Cannot Reach Service

#### Issue: Connection Timeout

```bash
# Check if service is running
ps aux | grep auth-service

# Check if port is open
netstat -tlnp | grep 8080

# Check firewall
sudo ufw status
sudo ufw allow 8080/tcp

# Test local connection
curl http://localhost:8080/health

# Test external connection
curl http://your-ip:8080/health
```

#### Issue: CORS Errors

```bash
# Error in browser console:
# Access to fetch at 'http://localhost:8080/api/auth/login' from origin 'http://localhost:3000'
# has been blocked by CORS policy

# Solution: Add CORS middleware
# See wiki/security.md for implementation

# Quick fix for development (NOT FOR PRODUCTION):
curl -X OPTIONS http://localhost:8080/api/auth/login -v
```

---

## Performance Issues

### Slow Response Times

#### Database Query Performance

```bash
# Enable query logging temporarily
# Edit postgresql.conf
log_statement = 'all'
log_duration = on
log_min_duration_statement = 1000  # Log queries taking >1s

# Reload PostgreSQL
sudo systemctl reload postgresql

# Check slow queries
tail -f /var/log/postgresql/postgresql-15-main.log

# Analyze query performance
psql $DATABASE_URL
EXPLAIN ANALYZE SELECT * FROM users WHERE email = 'user@example.com';

# Check if indexes exist
\d users
# Should see: "idx_users_email" btree (email)
```

#### High Memory Usage

```bash
# Check memory usage
ps aux | grep auth-service

# Check for memory leaks
# Use pprof
import _ "net/http/pprof"

# Access profiling endpoint
go tool pprof http://localhost:8080/debug/pprof/heap
```

#### High CPU Usage

```bash
# Profile CPU usage
go tool pprof http://localhost:8080/debug/pprof/profile?seconds=30

# Check for goroutine leaks
curl http://localhost:8080/debug/pprof/goroutine?debug=1
```

### Connection Pool Issues

```bash
# Too many database connections
# Error: pq: sorry, too many clients already

# Solution: Tune connection pool
db.SetMaxOpenConns(25)       // Maximum open connections
db.SetMaxIdleConns(5)        // Maximum idle connections
db.SetConnMaxLifetime(5 * time.Minute)  // Connection lifetime
db.SetConnMaxIdleTime(10 * time.Minute) // Idle connection lifetime
```

---

## Logging and Debugging

### Enable Debug Logging

```bash
# Set environment to development
export ENV=development

# This enables console logging with more details
```

### View Application Logs

```bash
# Binary deployment with systemd
sudo journalctl -u auth-service -f

# Docker
docker logs -f g-auth

# Docker Compose
docker-compose logs -f auth-service

# Kubernetes
kubectl logs -f -n auth-system -l app=auth-service

# Follow last 100 lines
kubectl logs -n auth-system -l app=auth-service --tail=100 -f
```

### Search Logs for Errors

```bash
# Systemd
journalctl -u auth-service | grep -i error

# Docker
docker logs g-auth 2>&1 | grep -i error

# Search for specific user's requests (by trace ID)
grep "trace_id:abc123" /var/log/auth-service.log
```

### Debug Specific Request

```bash
# Use curl with verbose output
curl -v -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password123"}'

# Check response headers
curl -I http://localhost:8080/health

# Test with different HTTP client
wget --debug http://localhost:8080/health
```

---

## FAQ

### Q: Why does my JWT token expire so quickly?

**A**: The default expiration is set to 1 minute for testing purposes. Change it in `internal/config/config.go`:

```go
JWTExpiration: 15 * time.Minute,  // or longer
```

### Q: How do I reset a user's password?

**A**: Currently there's no password reset endpoint. You can manually update in database:

```bash
# Generate new password hash
go run -c '
package main
import (
    "fmt"
    "golang.org/x/crypto/bcrypt"
)
func main() {
    hash, _ := bcrypt.GenerateFromPassword([]byte("newpassword"), 10)
    fmt.Println(string(hash))
}
'

# Update in database
psql $DATABASE_URL -c "UPDATE users SET password='$hash' WHERE email='user@example.com';"
```

### Q: How do I add more users for testing?

**A**: Use the registration endpoint:

```bash
for i in {1..10}; do
  curl -X POST http://localhost:8080/api/auth/register \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"user$i@example.com\",\"password\":\"Password123\",\"name\":\"User $i\"}"
done
```

### Q: Can I use this with a frontend application?

**A**: Yes, but you need to configure CORS. See [Security Guide](./security.md#cors-configuration).

### Q: How do I backup the database?

**A**: See [Deployment Guide](./deployment.md#backup-and-recovery):

```bash
pg_dump $DATABASE_URL > backup.sql

# Restore
psql $DATABASE_URL < backup.sql
```

### Q: How do I implement logout?

**A**: Implement token blacklist using Redis. See [Security Guide](./security.md#token-blacklist-for-logout).

### Q: Can I change the database to MySQL?

**A**: Yes, but you'll need to:
1. Create a new repository implementation for MySQL
2. Update the database driver import
3. Modify migration SQL syntax
4. Update connection string format

### Q: How do I run multiple instances?

**A**: The service is stateless and can be horizontally scaled:
- Use a load balancer (NGINX, HAProxy, AWS ALB)
- All instances connect to the same database
- No session state stored in memory

### Q: How do I secure the service in production?

**A**: Follow the [Security Checklist](./security.md#security-checklist):
- Enable HTTPS
- Use strong JWT secret
- Enable rate limiting
- Configure CORS properly
- Use database SSL
- Store secrets securely

---

## Getting Help

### Check Service Health

```bash
curl http://localhost:8080/health
# Expected: {"status":"ok"}
```

### Verify Database Connection

```bash
psql $DATABASE_URL -c "SELECT version();"
```

### Test Registration

```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"Test123","name":"Test User"}'
```

### Test Login

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"Test123"}'
```

### Test Protected Endpoint

```bash
# Get token from login response
TOKEN="your-jwt-token-here"

curl http://localhost:8080/api/me \
  -H "Authorization: Bearer $TOKEN"
```

---

## Still Having Issues?

If you're still experiencing problems:

1. **Check the logs** - Most errors are explained in logs
2. **Verify environment variables** - Ensure all required vars are set
3. **Test database connection** - Verify database is accessible
4. **Review recent changes** - What changed before the issue started?
5. **Check resource usage** - CPU, memory, disk space
6. **Restart the service** - Sometimes a simple restart helps

---

**Last Updated**: January 10, 2026
