# G-Auth - Go Authentication Service

A modern, production-ready authentication service built with Go, featuring JWT-based authentication, clean architecture, and comprehensive middleware support.

## 🚀 Features

- **User Registration & Authentication**: Secure user registration and login with JWT tokens
- **Email Verification**: Required email verification before login
- **Password Reset**: Secure password reset functionality with email tokens
- **Multi-Factor Authentication (MFA)**: Optional email-based MFA with 6-digit codes
- **Password Security**: bcrypt password hashing with proper salt rounds
- **Account Lockout**: Automatic account lockout after 5 failed login attempts (15-minute duration)
- **Clean Architecture**: Separation of concerns with domain, service, repository, and handler layers
- **Middleware Support**: 
  - Authentication middleware for protected routes
  - Request logging with structured logging (zap)
  - Distributed tracing with request IDs
  - API rate limiting per IP address to prevent abuse
- **Database**: PostgreSQL with connection pooling
- **API Documentation**: RESTful API design with proper HTTP status codes
- **Production Ready**: Configurable timeouts, graceful shutdown support

## 📋 Prerequisites

- Go 1.25.3 or higher
- PostgreSQL 15 or higher
- Docker (optional, for containerized deployment)

## 🛠️ Technology Stack

- **Language**: Go 1.25.3
- **Web Framework**: Gorilla Mux
- **Database**: PostgreSQL with lib/pq driver
- **Authentication**: JWT (golang-jwt/jwt)
- **Password Hashing**: bcrypt (golang.org/x/crypto)
- **Logging**: Uber Zap (structured logging)
- **Configuration**: godotenv for environment management
- **UUID**: Google UUID library
- **Email**: gomail for SMTP email sending

## 📁 Project Structure

```
g-auth/
├── cmd/
│   └── server/
│       └── main.go              # Application entry point
├── internal/
│   ├── config/
│   │   └── config.go            # Configuration management
│   ├── domain/
│   │   └── user.go              # Domain models and errors
│   ├── handler/
│   │   └── auth_handler.go      # HTTP handlers
│   ├── middleware/
│   │   ├── auth.go              # JWT authentication middleware
│   │   ├── logging.go           # Request logging middleware
│   │   ├── rate_limit.go        # Rate limiting middleware
│   │   └── trace.go             # Request tracing middleware
│   ├── repository/
│   │   ├── user_repository.go   # Repository interface
│   │   └── postgres/
│   │       └── user_repository.go # PostgreSQL implementation
│   └── service/
│       ├── auth_service.go      # Business logic layer
│       └── auth_service_test.go # Unit tests for auth service
├── migrations/
│   ├── 001_create_users_table.up.sql
│   ├── 001_create_users_table.down.sql
│   ├── 002_add_password_reset_fields.up.sql
│   └── 002_add_password_reset_fields.down.sql
├── pkg/
│   ├── jwt/
│   │   └── jwt.go               # JWT token management
│   ├── logger/
│   │   └── logger.go            # Logger initialization
│   ├── mailer/
│   │   └── mailer.go            # Email sending utilities
│   └── password/
│       └── password.go          # Password hashing utilities
├── wiki/                         # Documentation
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

## 🚦 Getting Started

### 1. Clone the Repository

```bash
git clone <repository-url>
cd g-auth
```

### 2. Set Up Environment Variables

Create a `.env` file in the root directory:

```env
APP_ENV=development
APP_PORT=8080
DATABASE_URL=postgres://postgres:postgres@localhost:5432/g-auth?sslmode=disable
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=your-email@gmail.com
RATE_LIMIT=10
RATE_LIMIT_BURST=20
```

> ⚠️ **Security Note**: Never commit the `.env` file to version control. Update `JWT_SECRET` in production.

### 3. Start PostgreSQL

#### Option A: Using Docker

```bash
make dev
```

This will:
- Start a PostgreSQL container
- Create the `g-auth` database
- Run all migrations automatically

Or use individual commands:

```bash
make docker-up     # Start PostgreSQL
make docker-migrate # Run migrations
```

#### Option B: Using Local PostgreSQL

```bash
# Ensure PostgreSQL is running
psql -U postgres -c "CREATE DATABASE g-auth;"

# Run all migrations
make migrate-up
```

Or run migrations individually:

```bash
make migrate-001-up  # Create users table
make migrate-002-up  # Add password reset fields
make migrate-003-up  # Add refresh token fields
make migrate-004-up  # Add email verification fields
make migrate-005-up  # Add account lockout fields
```

### 4. Install Dependencies

```bash
go mod download
```

### 5. Run the Service

```bash
make run
```

The service will start on `http://localhost:8080`

## 🧪 Testing

Run all tests:

```bash
make test
```

Run tests with coverage:

```bash
go test -v -cover ./...
```

Run tests for a specific package:

```bash
go test -v ./internal/service/
```

## 🔧 Available Make Commands

```bash
# Development
make help              # Show all available commands
make run               # Run the application
make build             # Build the application
make clean             # Clean build artifacts
make test              # Run all tests
make coverage          # Run tests with coverage report
make mod-tidy          # Tidy and verify go modules

# Database Migrations
make migrate-up        # Run all up migrations
make migrate-down      # Run all down migrations
make migrate-001-up    # Run migration 001 (users table) up
make migrate-001-down  # Run migration 001 (users table) down
make migrate-002-up    # Run migration 002 (password reset) up
make migrate-002-down  # Run migration 002 (password reset) down
make migrate-003-up    # Run migration 003 (refresh token) up
make migrate-003-down  # Run migration 003 (refresh token) down
make migrate-004-up    # Run migration 004 (email verification) up
make migrate-004-down  # Run migration 004 (email verification) down
make migrate-005-up    # Run migration 005 (account lockout) up
make migrate-005-down  # Run migration 005 (account lockout) down

# Docker
make docker-up         # Start PostgreSQL in Docker
make docker-down       # Stop and remove PostgreSQL Docker container
make docker-migrate    # Run migrations in Docker container
make docker-build      # Build Docker image
make docker-run        # Run service in Docker
make dev               # Set up complete development environment
```

## 🐳 Docker Deployment

### Build the Docker Image

```bash
make docker-build
```

### Run the Service

```bash
docker run -p 8080:8080 \
  -e DATABASE_URL="postgres://user:pass@host:5432/db" \
  -e JWT_SECRET="your-secret" \
  auth-service:latest
```

## 🔒 Security Considerations

1. **JWT Secret**: Use a strong, random JWT secret in production
2. **HTTPS**: Always use HTTPS in production
3. **Password Policy**: Implement password strength requirements
4. **Rate Limiting**: Configurable per-IP rate limiting implemented to prevent brute-force attacks
5. **CORS**: Configure CORS properly for your frontend
6. **Environment Variables**: Never commit secrets to version control
7. **SQL Injection**: All queries use parameterized statements
8. **Password Storage**: Passwords are hashed with bcrypt (cost factor 10)

## 📊 Monitoring & Logging

The service uses structured logging with Uber Zap:

- **Development**: Human-readable console output
- **Production**: JSON format for log aggregation

Each request is assigned a unique trace ID for distributed tracing.

## 🏗️ Architecture

The project follows **Clean Architecture** principles:

1. **Domain Layer**: Core business entities and rules
2. **Service Layer**: Business logic and use cases
3. **Repository Layer**: Data access abstraction
4. **Handler Layer**: HTTP request/response handling
5. **Middleware Layer**: Cross-cutting concerns (auth, logging, tracing)

### Key Design Patterns

- **Repository Pattern**: Abstracts data access
- **Dependency Injection**: All dependencies injected at initialization
- **Interface Segregation**: Small, focused interfaces
- **Single Responsibility**: Each component has one reason to change

## 🔒 Security Features

### Account Lockout
- **Failed Attempt Tracking**: Tracks consecutive failed login attempts per user
- **Automatic Lockout**: Accounts are locked after 5 consecutive failed attempts
- **Lockout Duration**: Accounts remain locked for 15 minutes
- **Automatic Unlock**: Accounts are automatically unlocked after the lockout period expires
- **Reset on Success**: Failed attempt counter resets to 0 on successful login
- **User-Friendly Messages**: Clear error messages inform users of lockout status, remaining attempts, and unlock times

### Other Security Measures
- **Password Security**: bcrypt password hashing with proper salt rounds
- **Rate Limiting**: API rate limiting per IP address to prevent abuse
- **JWT Authentication**: Secure token-based authentication
- **Email Verification**: Required email verification before login
- **Multi-Factor Authentication**: Optional email-based MFA for enhanced security
- **SQL Injection Prevention**: All queries use parameterized statements

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📞 Support

For issues and questions, please open an issue in the repository.

## 🗺️ Roadmap

### 🔐 Authentication & Security

- [x] Password reset
- [x] Refresh token
- [x] Email verification
- [x] API rate limiting
- [x] Account lockout
- [x] MFA
- [x] RBAC

- [ ] Audit logging
- [x] Password policy enforcement
- [ ] Refresh token rotation
- [ ] Token revocation
- [ ] Session & device management
- [ ] Suspicious activity detection
- [ ] Security headers & hardening
- [ ] Secrets management

---

### 🧱 Infrastructure & Reliability

- [ ] Graceful shutdown
- [ ] Health/readiness/liveness checks
- [ ] Structured logging
- [ ] Monitoring & alerting
- [ ] Distributed tracing
- [ ] Database migrations
- [ ] Backup & disaster recovery
- [ ] Zero-downtime deployment
- [ ] Resource limits & autoscaling
- [ ] Container security hardening

---

### 🌐 API & Platform

- [ ] Swagger/OpenAPI documentation
- [ ] API versioning
- [ ] Idempotency support
- [ ] User profile management
- [ ] GDPR compliance

---

### ⚙️ Background Processing

- [ ] Background jobs & queues
- [ ] Retry & dead-letter queue support
- [ ] Scheduled jobs

---

### 🧪 Testing & Quality

- [ ] Unit tests
- [ ] Integration tests
- [ ] E2E tests
- [ ] Coverage enforcement
- [ ] Linting & formatting
- [ ] Dependency vulnerability scanning

---

### 🚀 CI/CD & DevOps

- [ ] CI/CD pipeline
- [ ] Automated Docker builds
- [ ] Deployment automation
- [ ] Rollback strategy
- [ ] Semantic versioning

---

### 📚 Documentation

- [ ] Architecture documentation
- [ ] API documentation
- [ ] Deployment documentation
- [ ] Incident runbooks

## 📖 Additional Documentation

For more detailed documentation, see the [wiki](./wiki/) folder:

- [Architecture Overview](./wiki/architecture.md)
- [Deployment Guide](./wiki/deployment.md)
- [Mailer Configuration](./wiki/mailer.md)
- [Multi-Factor Authentication](./wiki/mfa.md)
- [API Documentation](./wiki/api-docs/)

---

**Built with ❤️ using Go**
