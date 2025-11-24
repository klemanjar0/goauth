# GoAuth - Authentication Service

A production-ready authentication service built with Go, featuring JWT-based authentication, refresh token rotation, and secure session management.

## Stack

- **HTTP Framework**: Chi router
- **Database**: PostgreSQL 16
- **Caching**: Redis 7
- **Message Queue**: Apache Kafka with Zookeeper
- **Password Hashing**: Argon2id
- **Token Hashing**: SHA-256
- **Query Generation**: sqlc
- **Migrations**: golang-migrate
- **Logging**: Zerolog
- **JWT**: golang-jwt/jwt v5
- **Metrics**: Prometheus (planned)

## Features

- ✅ User registration and login
- ✅ JWT-based access tokens (15 minutes)
- ✅ Refresh token rotation with PostgreSQL storage (7 days)
- ✅ Token blacklisting for logout
- ✅ Token reuse detection and family revocation
- ✅ User data caching with Redis
- ✅ Comprehensive audit logging
- ✅ Device tracking per refresh token
- ✅ Password reset flow with secure token hashing (SHA-256)
- ✅ Email verification with Kafka integration
- ✅ Automatic token revocation on password reset

---

## API Documentation

### Base URL
```
http://localhost:8080
```

### Authentication
Most endpoints require a Bearer token in the Authorization header:
```
Authorization: Bearer <access_token>
```

---

## Endpoints

### 1. Health Check

**GET** `/api/health`

Check if the service is running.

**Response** (200 OK):
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "service": "goauth"
}
```

---

### 2. User Registration

**POST** `/api/register`

Register a new user account.

**Request Body**:
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Validation**:
- Email must be valid format
- Password must be at least 8 characters
- Password must contain uppercase, lowercase, number, and special character

**Response** (201 Created):
```json
{
  "success": true,
  "data": {
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "email_confirmed": false,
    "is_active": true,
    "created_at": "2025-11-17T10:30:00Z"
  },
  "message": "user registered successfully"
}
```

**Error Responses**:

*409 Conflict* - User already exists:
```json
{
  "success": false,
  "error": {
    "message": "user with this email already exists"
  }
}
```

*400 Bad Request* - Invalid email:
```json
{
  "success": false,
  "error": {
    "message": "invalid email format"
  }
}
```

*400 Bad Request* - Weak password:
```json
{
  "success": false,
  "error": {
    "message": "password must contain uppercase, lowercase, number, and special character"
  }
}
```

---

### 3. User Login

**POST** `/api/login`

Authenticate a user and receive access + refresh tokens.

**Request Body**:
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Response** (200 OK):
```json
{
  "message": "login successful",
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "permissions": 0,
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_expires_in": 604800
}
```

**Token Information**:
- `access_token`: Short-lived token for API requests (15 minutes)
- `refresh_token`: Long-lived token for obtaining new access tokens (7 days)
- `expires_in`: Seconds until access token expires
- `refresh_expires_in`: Seconds until refresh token expires

**Error Responses**:

*401 Unauthorized* - Invalid credentials:
```json
{
  "success": false,
  "error": {
    "message": "invalid email or password"
  }
}
```

*403 Forbidden* - Inactive account:
```json
{
  "success": false,
  "error": {
    "message": "user account is inactive"
  }
}
```

---

### 4. Refresh Access Token

**POST** `/api/refresh`

Exchange a refresh token for a new access token and refresh token pair.

**Request Body**:
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response** (200 OK):
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_expires_in": 604800
}
```

**Security Features**:
- **Token Rotation**: Each refresh generates a new refresh token
- **Reuse Detection**: If a refresh token is used twice, the entire token family is revoked
- **Database Validation**: Refresh tokens are validated against PostgreSQL

**Error Responses**:

*401 Unauthorized* - Invalid or expired token:
```json
{
  "success": false,
  "error": {
    "message": "invalid token"
  }
}
```

*401 Unauthorized* - Token reuse detected:
```json
{
  "success": false,
  "error": {
    "message": "token has been revoked"
  }
}
```

---

### 5. Verify Access Token

**POST** `/api/verify-token`

Validate an access token and retrieve user information.

**Request Body**:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response** (200 OK):
```json
{
  "valid": true,
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "permissions": 0,
  "expires_at": "2025-11-17T12:45:00Z"
}
```

**Error Responses**:

*401 Unauthorized* - Expired token:
```json
{
  "success": false,
  "error": {
    "message": "token has expired"
  }
}
```

*401 Unauthorized* - Blacklisted token:
```json
{
  "success": false,
  "error": {
    "message": "token has been revoked"
  }
}
```

---

### 6. Logout

**POST** `/api/logout`

Invalidate the current access token by adding it to the blacklist.

**Headers**:
```
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "message": "logged out successfully"
}
```

**Notes**:
- The access token is added to Redis blacklist until its natural expiration
- Refresh tokens remain valid; revoke them separately if needed
- Logout is idempotent (calling it with an expired token still succeeds)

**Error Responses**:

*401 Unauthorized* - Missing authorization header:
```json
{
  "success": false,
  "error": {
    "message": "authorization header required"
  }
}
```

---

### 7. Request Password Reset

**POST** `/api/password-reset/request`

Request a password reset email with a secure token.

**Request Body**:
```json
{
  "email": "user@example.com"
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "message": "if the email exists, a password reset link has been sent"
}
```

**Security Features**:
- Returns success even if email doesn't exist (prevents email enumeration)
- Token is SHA-256 hashed before storage
- Token expires in 24 hours
- Rate limiting recommended

**Notes**:
- Password reset email is queued via Kafka
- Inactive users won't receive reset emails (but response stays the same)

---

### 8. Reset Password

**POST** `/api/password-reset/confirm`

Reset user password using the token from email.

**Request Body**:
```json
{
  "token": "550e8400-e29b-41d4-a716-446655440000",
  "new_password": "NewSecurePassword123!"
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "message": "password has been reset successfully"
}
```

**Validation**:
- Password must meet security requirements
- Token must be valid and not expired
- Token can only be used once

**Security Actions**:
- All user refresh tokens are revoked
- User cache is invalidated
- Audit log is created
- Password is hashed with Argon2id

**Error Responses**:

*400 Bad Request* - Weak password:
```json
{
  "success": false,
  "error": {
    "message": "password too weak"
  }
}
```

*401 Unauthorized* - Invalid/expired token:
```json
{
  "success": false,
  "error": {
    "message": "invalid token"
  }
}
```

---

### 9. Verify Email

**POST** `/api/email-verification/verify`

Verify user email using the token from verification email.

**Request Body**:
```json
{
  "token": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response** (200 OK):
```json
{
  "success": true,
  "message": "email verified successfully"
}
```

**Security Features**:
- Token can only be used once
- Token expires in 24 hours
- User cache is invalidated after verification

**Error Responses**:

*401 Unauthorized* - Invalid/expired token:
```json
{
  "success": false,
  "error": {
    "message": "invalid token"
  }
}
```

---

## Token Architecture

### Access Tokens (JWT)
- **Storage**: Not stored (stateless)
- **Expiration**: 15 minutes
- **Purpose**: API authentication
- **Claims**: `user_id`, `iat`, `exp`
- **Revocation**: Redis blacklist on logout

### Refresh Tokens (JWT + Database)
- **Storage**: PostgreSQL with metadata
- **Expiration**: 7 days
- **Purpose**: Obtain new access tokens
- **Claims**: `token_id` (subject), `iat`, `exp`
- **Rotation**: New token issued on every refresh
- **Revocation**: Database-backed with family chain

### Complete Database Schema

```sql
-- Users Table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    permissions BIGINT NOT NULL DEFAULT 0,
    is_active BOOL DEFAULT TRUE,
    email_confirmed BOOL DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Refresh Tokens Table
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    device_info TEXT,
    rotated_from UUID REFERENCES refresh_tokens(id),
    revoked BOOL DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ
);

-- Email Verification Tokens Table
CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Password Reset Tokens Table
CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Audit Logs Table
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NULL,
    event_type TEXT NOT NULL,
    ip INET,
    ua TEXT,
    payload JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

### Security Flow

**Token Refresh with Rotation**:
```
1. Client sends refresh_token JWT
2. Server validates JWT signature and expiration
3. Server extracts token_id from JWT subject
4. Server queries PostgreSQL for token record
5. Server checks if token was already used (last_used_at)
   - If used → Revoke entire token family (attack detected!)
6. Server marks token as used (last_used_at = NOW)
7. Server creates new refresh token in DB (rotated_from = old_token_id)
8. Server generates new access + refresh token JWTs
9. Client receives new token pair
```

**Token Reuse Detection**:
```
Scenario: Attacker steals refresh token

1. Legitimate user refreshes token → Success
2. Attacker tries to use stolen token
3. Server detects last_used_at is set
4. Server revokes entire token family using recursive query
5. Both attacker and user must re-authenticate
```

---

## Redis Keys

### Access Token Blacklist
```
Key:   blacklist:access:{full_token_string}
Value: "revoked"
TTL:   Until token's natural expiration (15 minutes max)
```

### User Data Cache
```
Key:   user:{user_id}
Value: JSON-serialized user object
TTL:   5 minutes
```

---

## Error Codes

| HTTP Status | Error Message | Description |
|------------|--------------|-------------|
| 400 | invalid email format | Email validation failed |
| 400 | password must contain... | Password too weak |
| 400 | invalid request body | Malformed JSON |
| 401 | invalid email or password | Authentication failed |
| 401 | invalid token | Token validation failed |
| 401 | token has expired | Token past expiration |
| 401 | token has been revoked | Token in blacklist |
| 403 | user account is inactive | Account disabled |
| 409 | user with this email already exists | Duplicate registration |
| 500 | server internal error | Unexpected server error |

---

## Development Roadmap

### Implemented ✅
- [x] User registration with validation
- [x] Login with JWT generation
- [x] Refresh token rotation (PostgreSQL)
- [x] Token blacklisting (Redis)
- [x] Token reuse detection
- [x] User data caching
- [x] Audit logging
- [x] Device tracking
- [x] Email verification flow with Kafka
- [x] Password reset flow with secure tokens
- [x] Automatic token revocation on password reset
- [x] SHA-256 token hashing
- [x] Email enumeration protection

### In Progress 🚧
- [ ] Email consumer service (Kafka → SMTP)
- [ ] Rate limiting middleware
- [ ] Admin endpoints for user management

### Planned 🔮
- [ ] OAuth2 providers (Google, GitHub)
- [ ] Multi-factor authentication (MFA)
- [ ] Session management dashboard
- [ ] Prometheus metrics
- [ ] Grafana dashboards
- [ ] Account lockout after failed attempts
- [ ] IP-based security rules

---

## Environment Variables

```env
# Database
DATABASE_URL=postgres://postgres:password@localhost:5432/goauth?sslmode=disable

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=password

# Kafka
KAFKA_BROKERS=localhost:9092
KAFKA_EMAIL_TOPIC=email-notifications

# Server
PORT=8080
HOST=0.0.0.0

# JWT Secrets (CHANGE IN PRODUCTION!)
JWT_ACCESS_SECRET=your-secret-key-min-32-chars-here-change-this
JWT_REFRESH_SECRET=your-refresh-secret-key-min-32-chars-here-change-this

# Email (for future SMTP integration)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
```

---

## Running the Service

### Using Docker Compose (Recommended)

```bash
# Start all dependencies (PostgreSQL, Redis, Kafka, Zookeeper)
docker-compose up -d

# Check service health
docker-compose ps

# View logs
docker-compose logs -f

# Stop services
docker-compose down

# Stop and remove volumes (clean slate)
docker-compose down -v
```

### Database Setup

```bash
# Run migrations
make migrate-up

# Rollback last migration
make migrate-down

# Force migration version (if stuck)
make migrate-force VERSION=1
```

### Running the Application

```bash
# Development mode
go run cmd/authsvc/main.go

# Build and run
make build
./bin/authsvc

# Run with hot reload (if using air)
air
```

### Generate SQL Code (sqlc)

```bash
# Generate Go code from SQL queries
make sqlc-generate

# Verify SQL queries
make sqlc-verify
```

### Quick Start Commands

```bash
# First time setup
make setup

# Quick start (assumes dependencies installed)
make quickstart

# View all available commands
make help
```

---

## Service URLs

When running with `docker-compose up -d`:

| Service | URL | Description |
|---------|-----|-------------|
| GoAuth API | http://localhost:8080 | Main authentication service |
| Adminer | http://localhost:8080 | PostgreSQL web UI (use port 8080) |
| PostgreSQL | localhost:5432 | Database server |
| Redis | localhost:6379 | Cache server |
| Kafka | localhost:9092 | Message broker |
| Kafka UI | http://localhost:8090 | Kafka management UI |

**Adminer Login:**
- System: `PostgreSQL`
- Server: `postgres`
- Username: `postgres`
- Password: `password`
- Database: `goauth`

---

## Makefile Commands

The project includes a comprehensive Makefile for common tasks:

### Development
```bash
make run              # Run the application
make build            # Build the application binary
make clean            # Remove build artifacts
make test             # Run tests
make test-coverage    # Run tests with coverage report
```

### Docker
```bash
make docker-up        # Start all Docker services
make docker-down      # Stop all Docker services
make docker-logs      # View Docker logs (follow mode)
make docker-clean     # Stop and remove all volumes
```

### Database
```bash
make migrate-up       # Run all migrations
make migrate-down     # Rollback last migration
make migrate-force VERSION=1  # Force migration version
make migrate-create NAME=add_users  # Create new migration
make db-reset         # Reset database (down + up)
```

### Code Generation
```bash
make sqlc-generate    # Generate Go code from SQL
make sqlc-verify      # Verify SQL queries
```

### Development Tools
```bash
make fmt              # Format Go code
make lint             # Run linter (requires golangci-lint)
make deps             # Download dependencies
make mod-tidy         # Tidy go.mod
```

### Quick Commands
```bash
make help             # Show all available commands
make setup            # Complete development setup
make quickstart       # Start dependencies + migrations
```

---

## Example Usage

### Complete Authentication Flow

```bash
# 1. Register a new user
curl -X POST http://localhost:8080/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "password": "SecurePass123!"
  }'

# 2. Login
curl -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "password": "SecurePass123!"
  }'

# Save the access_token and refresh_token from response

# 3. Make authenticated request (example: verify token)
curl -X POST http://localhost:8080/api/verify-token \
  -H "Content-Type: application/json" \
  -d '{
    "token": "<access_token>"
  }'

# 4. Refresh access token when it expires
curl -X POST http://localhost:8080/api/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "<refresh_token>"
  }'

# 5. Logout
curl -X POST http://localhost:8080/api/logout \
  -H "Authorization: Bearer <access_token>"
```

---

## License

MIT