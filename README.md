# GoAuth - Authentication Service

A production-ready authentication service built with Go, featuring JWT-based authentication, refresh token rotation, and secure session management.

## Stack

- **HTTP Framework**: Chi router
- **Database**: PostgreSQL
- **Caching**: Redis
- **Password Hashing**: Argon2id
- **Query Generation**: sqlc
- **Migrations**: golang-migrate
- **Logging**: Zerolog
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
- 🚧 Password reset flow
- 🚧 Email verification

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

### Database Schema (Refresh Tokens)
```sql
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    device_info TEXT,
    rotated_from UUID REFERENCES refresh_tokens(id),
    revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ
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

### Planned 🚧
- [ ] Email verification flow
- [ ] Password reset flow
- [ ] Rate limiting
- [ ] OAuth2 providers (Google, GitHub)
- [ ] Multi-factor authentication (MFA)
- [ ] Session management dashboard
- [ ] Prometheus metrics

---

## Environment Variables

```env
# Database
DATABASE_URL=postgres://user:password@localhost:5432/goauth?sslmode=disable

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=password

# Server
PORT=8080

# JWT Secrets (CHANGE IN PRODUCTION!)
JWT_ACCESS_SECRET=your-secret-key-min-32-chars
JWT_REFRESH_SECRET=your-refresh-secret-key-min-32-chars
```

---

## Running the Service

```bash
# Start dependencies
docker-compose up -d

# Run migrations
make migrate-up

# Start server
go run cmd/authsvc/main.go
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