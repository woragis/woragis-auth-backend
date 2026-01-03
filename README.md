# Auth Service

Authentication and authorization service for Woragis platform.

## Overview

The Auth Service is a standalone microservice responsible for:
- User registration and authentication
- JWT token management (access and refresh tokens)
- User profile management
- Session management (multi-device support)
- Email verification
- Password management
- Admin user management

## Architecture

This service follows the same patterns as the main Woragis backend:
- **Go Fiber** web framework
- **GORM** for database operations
- **PostgreSQL** for data persistence
- **Redis** for caching and session storage
- **OpenTelemetry** for distributed tracing
- **Prometheus** for metrics
- **Structured logging** with trace ID support

## Project Structure

```
auth/
├── server/                    # Go application
│   ├── cmd/
│   │   └── server/
│   │       └── main.go       # Application entry point
│   ├── internal/
│   │   ├── config/           # Configuration management
│   │   ├── database/         # Database connection and management
│   │   └── domains/
│   │       └── auth/         # Auth domain (business logic)
│   └── pkg/                  # Shared packages
│       ├── auth/             # JWT and password utilities
│       ├── health/           # Health check utilities
│       ├── logger/           # Structured logging
│       ├── metrics/          # Prometheus metrics
│       ├── middleware/       # Fiber middleware
│       ├── security/         # Security middleware
│       ├── timeout/          # Timeout utilities
│       ├── tracing/          # OpenTelemetry tracing
│       └── utils/            # Utility functions
├── docker-compose.yml        # Development environment
├── docker-compose.test.yml   # Test environment
└── .github/
    └── workflows/            # CI/CD pipelines
```

## API Endpoints

### Public Endpoints

- `POST /api/v1/auth/register` - Register a new user
- `POST /api/v1/auth/login` - Authenticate user
- `POST /api/v1/auth/refresh` - Refresh access token
- `POST /api/v1/auth/logout` - Logout user
- `GET /api/v1/auth/verify-email` - Verify email address

### Protected Endpoints (Require Authentication)

- `GET /api/v1/auth/profile` - Get user profile
- `PUT /api/v1/auth/profile` - Update user profile
- `POST /api/v1/auth/change-password` - Change password
- `POST /api/v1/auth/logout-all` - Logout from all devices

### Admin Endpoints (Require Admin Role)

- `GET /api/v1/auth/admin/users/:id` - Get user by ID
- `GET /api/v1/auth/admin/users` - List all users
- `POST /api/v1/auth/admin/cleanup` - Cleanup expired sessions

### System Endpoints

- `GET /healthz` - Health check
- `GET /metrics` - Prometheus metrics

## Environment Variables

```bash
# Application
APP_ENV=development
APP_NAME=auth-service
APP_PORT=3000

# Database
DATABASE_URL=postgres://user:password@localhost:5432/auth_service?sslmode=disable
POSTGRES_USER=woragis
POSTGRES_PASSWORD=password
POSTGRES_DB=auth_service

# Redis
REDIS_URL=redis://localhost:6379/0

# JWT
AUTH_JWT_SECRET=your-secret-key
AUTH_JWT_TTL=24h
AUTH_JWT_REFRESH_TTL=168h
AUTH_BCRYPT_COST=12

# CORS
CORS_ENABLED=true
CORS_ALLOWED_ORIGINS=http://localhost:5173

# Monitoring
OTLP_ENDPOINT=http://jaeger:4318
JAEGER_ENDPOINT=http://jaeger:4318
```

## Development

### Prerequisites

- Go 1.25.1+
- Docker and Docker Compose
- PostgreSQL 15+
- Redis 7+

### Running Locally

1. **Start dependencies:**
   ```bash
   docker-compose up -d database redis
   ```

2. **Run migrations:**
   ```bash
   cd server
   go run cmd/server/main.go
   ```
   (Migrations run automatically on startup)

3. **Run the service:**
   ```bash
   cd server
   go run cmd/server/main.go
   ```

### Running with Docker Compose

```bash
docker-compose up -d
```

The service will be available at `http://localhost:3000`

## Testing

### Run Tests

```bash
cd server
go test ./...
```

### Integration Tests

```bash
docker-compose -f docker-compose.test.yml up -d
cd server
go test -tags=integration ./...
```

## CI/CD

The service has its own CI/CD pipeline:

- **CI**: Runs on push/PR to `main` or `develop` branches
  - Unit tests
  - Integration tests
  - Linting
  - Docker build

- **CD**: Runs on version tag push (e.g., `v1.0.0`)
  - Build and push Docker image
  - Deploy to production

## Database Schema

The service creates the following tables:
- `users` - User accounts
- `profiles` - User profiles
- `sessions` - User sessions
- `verification_tokens` - Email verification and password reset tokens

## Security Features

- **Password Hashing**: Bcrypt with configurable cost
- **JWT Tokens**: Secure access and refresh tokens
- **Session Management**: Multi-device session tracking
- **Rate Limiting**: 100 requests per minute per IP/user
- **Security Headers**: Helmet middleware for security headers
- **Input Sanitization**: Automatic input sanitization
- **Request Size Limits**: 10MB maximum request size

## Monitoring

- **Health Checks**: `/healthz` endpoint
- **Metrics**: `/metrics` endpoint (Prometheus)
- **Tracing**: OpenTelemetry integration with Jaeger
- **Logging**: Structured JSON logging with trace IDs

## Integration with Other Services

This service is designed to be called by other Woragis services:
- **Jobs Service**: Validates JWT tokens
- **Management Service**: Validates JWT tokens
- **Posts Service**: Validates JWT tokens
- **Social Media Service**: Validates JWT tokens

All services should call the Auth Service to:
- Validate JWT tokens
- Get user information
- Check user roles and permissions

## License

Proprietary - Woragis Platform

