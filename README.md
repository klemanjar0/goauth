# PLAN OF DEVELOPMENT

### Required endpoints

POST /auth/register
POST /auth/login
POST /auth/logout
POST /auth/refresh
POST /auth/forgot-password
POST /auth/reset-password
GET  /auth/me
GET  /auth/health

### Stack

REST Specification - chi
DB - postgres
Caching - redis
Pass hash - argon2id
Queries - sqlc
Migrations - golang-migrate
Logging - zap
Metrics - prometheus