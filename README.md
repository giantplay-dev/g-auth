# G-Auth - Go Authentication Service

A modern, production-ready authentication service built with Go, featuring JWT-based authentication, clean architecture, and comprehensive middleware support.

## 🚀 Features

- **User Registration & Authentication**: Secure user registration and login with JWT tokens
- **Password Security**: bcrypt password hashing with proper salt rounds
- **Clean Architecture**: Separation of concerns with domain, service, repository, and handler layers
- **Middleware Support**: 
  - Authentication middleware for protected routes
  - Request logging with structured logging (zap)
  - Distributed tracing with request IDs
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
│   │   └── trace.go             # Request tracing middleware
│   ├── repository/
│   │   ├── user_repository.go   # Repository interface
│   │   └── postgres/
│   │       └── user_repository.go # PostgreSQL implementation
│   └── service/
│       └── auth_service.go      # Business logic layer
├── migrations/
│   ├── 001_create_users_table.up.sql
│   └── 001_create_users_table.down.sql
├── pkg/
│   ├── jwt/
│   │   └── jwt.go               # JWT token management
│   ├── logger/
│   │   └── logger.go            # Logger initialization
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
ENV=development
PORT=8080
DATABASE_URL=postgres://postgres:postgres@localhost:5432/authdb?sslmode=disable
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production
```

> ⚠️ **Security Note**: Never commit the `.env` file to version control. Update `JWT_SECRET` in production.

### 3. Start PostgreSQL

#### Option A: Using Docker

```bash
make docker-up
```

This will:
- Start a PostgreSQL container
- Create the `authdb` database
- Run migrations automatically

#### Option B: Using Local PostgreSQL

```bash
# Ensure PostgreSQL is running
psql -U postgres -c "CREATE DATABASE authdb;"

# Run migrations
make migrate-up
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

## 📚 API Documentation

### Base URL
```
http://localhost:8080/api
```

### Endpoints

#### 1. Health Check
```http
GET /health
```

**Response:**
```json
{
  "status": "ok"
}
```

#### 2. Register User
```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecureP@ssw0rd",
  "name": "John Doe"
}
```

**Success Response (201 Created):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "email": "user@example.com",
    "name": "John Doe",
    "created_at": "2026-01-10T10:00:00Z",
    "updated_at": "2026-01-10T10:00:00Z"
  }
}
```

**Error Response (409 Conflict):**
```json
{
  "error": "user already exists"
}
```

#### 3. Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecureP@ssw0rd"
}
```

**Success Response (200 OK):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "email": "user@example.com",
    "name": "John Doe",
    "created_at": "2026-01-10T10:00:00Z",
    "updated_at": "2026-01-10T10:00:00Z"
  }
}
```

**Error Response (401 Unauthorized):**
```json
{
  "error": "invalid credentials"
}
```

#### 4. Get Current User (Protected)
```http
GET /api/me
Authorization: Bearer <jwt-token>
```

**Success Response (200 OK):**
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "email": "user@example.com",
  "name": "John Doe",
  "created_at": "2026-01-10T10:00:00Z",
  "updated_at": "2026-01-10T10:00:00Z"
}
```

**Error Response (401 Unauthorized):**
```json
{
  "error": "missing or invalid authorization header"
}
```

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
make run           # Run the service locally
make build         # Build the binary to ./bin/auth-service
make test          # Run all tests
make migrate-up    # Run database migrations
make migrate-down  # Rollback database migrations
make docker-up     # Start PostgreSQL in Docker
make docker-down   # Stop and remove PostgreSQL container
make docker-build  # Build Docker image for the service
make docker-run    # Run the service in Docker
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
4. **Rate Limiting**: Add rate limiting to prevent brute-force attacks
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

- [ ] Add password reset functionality
- [ ] Implement refresh token mechanism
- [ ] Add email verification
- [ ] Implement role-based access control (RBAC)
- [ ] Add OAuth2 integration (Google, GitHub)
- [ ] Add API rate limiting
- [ ] Implement account lockout after failed attempts
- [ ] Add comprehensive API documentation with Swagger
- [ ] Implement graceful shutdown
- [ ] Add health check with database status

## 📖 Additional Documentation

For more detailed documentation, see the [wiki](./wiki/) folder:

- [Architecture Overview](./wiki/architecture.md)
- [API Reference](./wiki/api-reference.md)
- [Deployment Guide](./wiki/deployment.md)
- [Security Best Practices](./wiki/security.md)
- [Troubleshooting](./wiki/troubleshooting.md)

---

**Built with ❤️ using Go**
