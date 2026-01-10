# Architecture Overview

## Table of Contents
- [Architecture Principles](#architecture-principles)
- [System Architecture](#system-architecture)
- [Layer Description](#layer-description)
- [Data Flow](#data-flow)
- [Component Relationships](#component-relationships)
- [Design Patterns](#design-patterns)
- [Scalability Considerations](#scalability-considerations)

## Architecture Principles

The g-auth service follows **Clean Architecture** principles with clear separation of concerns:

1. **Independence of Frameworks**: Business logic doesn't depend on external frameworks
2. **Testability**: Business rules can be tested without UI, database, or external elements
3. **Independence of UI**: The UI can change without changing business rules
4. **Independence of Database**: Business rules are not bound to the database
5. **Independence of External Services**: Business rules don't know anything about interfaces to the outside world

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         HTTP Requests                            │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Middleware Layer                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   Tracing    │  │   Logging    │  │     Auth     │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Handler Layer                                 │
│                  (HTTP Request/Response)                         │
│                    auth_handler.go                               │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Service Layer                                 │
│                   (Business Logic)                               │
│                   auth_service.go                                │
│  ┌──────────────┐              ┌──────────────┐                 │
│  │  JWT Manager │              │  Password    │                 │
│  │  (pkg/jwt)   │              │  (pkg/password)                │
│  └──────────────┘              └──────────────┘                 │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Repository Layer                                │
│                 (Data Access Interface)                          │
│                  user_repository.go                              │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│               PostgreSQL Implementation                          │
│              postgres/user_repository.go                         │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    PostgreSQL Database                           │
└─────────────────────────────────────────────────────────────────┘
```

## Layer Description

### 1. Domain Layer (`internal/domain/`)

**Purpose**: Defines core business entities and rules

**Components**:
- `User`: Core user entity
- `LoginRequest`, `RegisterRequest`: Input DTOs
- `AuthResponse`: Output DTOs
- Domain errors: `ErrUserNotFound`, `ErrUserAlreadyExists`, `ErrInvalidCredentials`

**Characteristics**:
- No external dependencies
- Pure Go structs and interfaces
- Contains business validation rules
- Defines domain-specific errors

**Example**:
```go
type User struct {
    ID        uuid.UUID `json:"id"`
    Email     string    `json:"email"`
    Password  string    `json:"-"` // Never exposed in JSON
    Name      string    `json:"name"`
    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
}
```

### 2. Handler Layer (`internal/handler/`)

**Purpose**: Handles HTTP requests and responses

**Responsibilities**:
- Parse HTTP requests
- Validate request format
- Call service layer
- Format HTTP responses
- Set appropriate status codes
- Route configuration

**Key Methods**:
- `Register(w http.ResponseWriter, r *http.Request)`
- `Login(w http.ResponseWriter, r *http.Request)`
- `GetMe(w http.ResponseWriter, r *http.Request)`
- `Health(w http.ResponseWriter, r *http.Request)`

**Error Handling**:
- Maps domain errors to HTTP status codes
- Returns consistent error response format
- Logs errors without exposing internal details

### 3. Service Layer (`internal/service/`)

**Purpose**: Contains business logic and use cases

**Responsibilities**:
- User registration workflow
- User authentication
- Password validation
- JWT token generation
- Business rule enforcement
- Orchestrates repository calls

**Dependencies**:
- UserRepository interface
- JWT Manager
- Password utilities

**Key Methods**:
- `Register(ctx context.Context, req *domain.RegisterRequest) (*domain.AuthResponse, error)`
- `Login(ctx context.Context, req *domain.LoginRequest) (*domain.AuthResponse, error)`
- `GetUserByID(ctx context.Context, userID uuid.UUID) (*domain.User, error)`

### 4. Repository Layer (`internal/repository/`)

**Purpose**: Abstracts data access

**Structure**:
- **Interface** (`user_repository.go`): Defines data access contract
- **Implementation** (`postgres/user_repository.go`): PostgreSQL-specific implementation

**Interface Methods**:
```go
type UserRepository interface {
    Create(ctx context.Context, user *domain.User) error
    GetByEmail(ctx context.Context, email string) (*domain.User, error)
    GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
}
```

**Benefits**:
- Easy to swap database implementations
- Facilitates testing with mock repositories
- Decouples business logic from data access

### 5. Middleware Layer (`internal/middleware/`)

**Purpose**: Cross-cutting concerns

**Components**:

#### Authentication Middleware (`auth.go`)
- Validates JWT tokens
- Extracts user ID from token
- Adds user context to request
- Protects routes

#### Logging Middleware (`logging.go`)
- Logs all HTTP requests
- Records response status and duration
- Uses structured logging (zap)
- Logs request method, path, status, and duration

#### Tracing Middleware (`trace.go`)
- Generates unique request IDs
- Adds trace ID to request context
- Enables distributed tracing
- Helps with debugging and log correlation

### 6. Package Layer (`pkg/`)

**Purpose**: Reusable utilities and helpers

#### JWT Package (`pkg/jwt/`)
- JWT token generation
- Token validation
- Claims extraction
- Token expiration handling

#### Logger Package (`pkg/logger/`)
- Logger initialization
- Environment-based configuration
- Structured logging setup (zap)

#### Password Package (`pkg/password/`)
- Password hashing (bcrypt)
- Password verification
- Secure default cost factor (10)

## Data Flow

### Registration Flow

```
1. Client sends POST /api/auth/register
   ↓
2. TraceMiddleware: Adds trace ID
   ↓
3. LoggingMiddleware: Logs request
   ↓
4. Handler: Parses JSON request
   ↓
5. Service: Validates business rules
   ↓
6. Service: Hashes password (bcrypt)
   ↓
7. Repository: Inserts user into database
   ↓
8. Service: Generates JWT token
   ↓
9. Handler: Returns AuthResponse with token and user
   ↓
10. LoggingMiddleware: Logs response
```

### Login Flow

```
1. Client sends POST /api/auth/login
   ↓
2. Middleware: Tracing + Logging
   ↓
3. Handler: Parses credentials
   ↓
4. Service: Fetches user by email
   ↓
5. Service: Verifies password (bcrypt)
   ↓
6. Service: Generates JWT token
   ↓
7. Handler: Returns AuthResponse
```

### Protected Route Flow

```
1. Client sends GET /api/me with Authorization header
   ↓
2. TraceMiddleware: Adds trace ID
   ↓
3. LoggingMiddleware: Logs request
   ↓
4. AuthMiddleware: Validates JWT token
   ↓
5. AuthMiddleware: Extracts user ID, adds to context
   ↓
6. Handler: Retrieves user ID from context
   ↓
7. Service: Fetches user by ID
   ↓
8. Handler: Returns user data
```

## Component Relationships

### Dependency Graph

```
main.go
  │
  ├── config.Load()
  ├── logger.NewLogger()
  ├── sql.Open() → db
  │
  ├── jwt.NewJWTManager()
  ├── postgres.NewUserRepository(db)
  │
  ├── service.NewAuthService(repo, jwtManager)
  │
  └── handler.NewAuthHandler(service)
        │
        └── router with middleware
```

### Dependency Injection

All dependencies are injected at initialization:

```go
// Initialize dependencies
jwtManager := jwt.NewJWTManager(cfg.JWTSecret, cfg.JWTExpiration)
userRepo := postgres.NewUserRepository(db)
authService := service.NewAuthService(userRepo, jwtManager)
handler := handler.NewAuthHandler(authService)
```

**Benefits**:
- Easy to test with mocks
- Explicit dependencies
- Compile-time dependency checking
- Flexible configuration

## Design Patterns

### 1. Repository Pattern
Abstracts data access behind an interface, allowing different implementations.

### 2. Dependency Injection
All dependencies are injected through constructors, not created internally.

### 3. Middleware Pattern
Cross-cutting concerns are implemented as composable middleware functions.

### 4. Factory Pattern
Used for creating loggers, JWT managers, and other components.

### 5. Error Wrapping
Domain-specific errors are defined and returned, allowing proper error handling at each layer.

### 6. Context Propagation
Go context is used throughout for cancellation, deadlines, and request-scoped values.

## Scalability Considerations

### Current Architecture Supports:

1. **Horizontal Scaling**
   - Stateless service design
   - No in-memory session storage
   - All state in PostgreSQL

2. **Database Scaling**
   - Connection pooling configured
   - Can add read replicas
   - Prepared statements for performance

3. **Caching Opportunities**
   - Redis can be added for session storage
   - User profile caching
   - JWT blacklist for logout

4. **Load Balancing**
   - Stateless design works with any load balancer
   - No sticky sessions required

### Future Enhancements:

1. **Microservices Split**
   - Auth service (current)
   - User profile service
   - Session management service

2. **Event-Driven Architecture**
   - Publish user registration events
   - Subscribe to user update events
   - Message queue integration (Kafka, RabbitMQ)

3. **API Gateway**
   - Centralized authentication
   - Rate limiting
   - Request routing

4. **Service Mesh**
   - Istio/Linkerd for service-to-service communication
   - Distributed tracing
   - Circuit breakers

## Testing Strategy

### Unit Tests
- Service layer: Mock repository
- Repository layer: Test database or in-memory database
- JWT utilities: Test token generation and validation
- Password utilities: Test hashing and verification

### Integration Tests
- Handler layer: Test with test server
- Full request/response cycle
- Database integration

### Contract Tests
- API contract testing
- Ensure backward compatibility

## Configuration Management

Configuration is loaded from environment variables with defaults:

```go
type Config struct {
    Env           string        // development, staging, production
    Port          string        // Server port
    DatabaseURL   string        // PostgreSQL connection string
    JWTSecret     string        // JWT signing key
    JWTExpiration time.Duration // Token expiration time
}
```

**Environment-Based Behavior**:
- **Development**: Console logging, verbose errors
- **Production**: JSON logging, minimal error exposure

## Security Architecture

### Authentication Flow

1. User provides credentials
2. Credentials validated against database
3. JWT token generated with user ID
4. Token returned to client
5. Client includes token in subsequent requests
6. Middleware validates token on protected routes

### Security Layers

1. **Password Security**: bcrypt hashing with salt
2. **Token Security**: JWT with HMAC-SHA256
3. **SQL Injection Prevention**: Parameterized queries
4. **Secrets Management**: Environment variables, never hardcoded

### Future Security Enhancements

- [ ] Refresh token mechanism
- [ ] Token revocation/blacklist
- [ ] Rate limiting per user/IP
- [ ] Account lockout after failed attempts
- [ ] IP whitelisting/blacklisting
- [ ] 2FA support

## Monitoring & Observability

### Current Implementation

1. **Structured Logging**: Uber Zap
2. **Request Tracing**: Unique trace IDs per request
3. **HTTP Logging**: Method, path, status, duration

### Recommended Additions

1. **Metrics**: Prometheus metrics
   - Request count
   - Response time
   - Error rate
   - Active users

2. **APM**: Application Performance Monitoring
   - New Relic, Datadog, or similar
   - Database query performance
   - External API calls

3. **Health Checks**
   - Database connectivity
   - Dependency health
   - Memory/CPU usage

## Error Handling Strategy

### Error Hierarchy

```
Domain Errors (internal/domain)
  ├── ErrUserNotFound (404)
  ├── ErrUserAlreadyExists (409)
  └── ErrInvalidCredentials (401)

Service Errors (internal/service)
  ├── Wraps domain errors
  └── Adds context

Handler Layer
  └── Maps to HTTP status codes
```

### Error Response Format

```json
{
  "error": "human-readable error message"
}
```

### Logging Strategy

- **Info**: Successful operations
- **Error**: Failed operations with context
- **Fatal**: Startup failures

---

**Last Updated**: January 10, 2026
