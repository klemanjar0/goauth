package failure

import "errors"

// -- Server Errors Declarations --
var (
	ErrEnvironmentVariable    = errors.New("environment variable missing")
	ErrEnvironmentLocalFile   = errors.New("no .env file found, using system environment variables")
	ErrEnvironmentDatabase    = errors.New("no database connection string found")
	ErrEnvironmentPort        = errors.New("port env variable is missing. applying default port 8080")
	ErrDatabaseInitialization = errors.New("database failed to init")
	ErrDatabaseMigration      = errors.New("database failed to run migrations")
	ErrPoolConnection         = errors.New("failed to parse pool config")
	ErrPoolCreate             = errors.New("failed to create pool")
	ErrFailedToStartServer    = errors.New("server failed to start")
	ErrForcedShutdownServer   = errors.New("server forced to shutdown")
	ErrRedisClient            = errors.New("failed to connect to redis")
	ErrServer                 = errors.New("server internal error")
	ErrConfigInitFailed       = errors.New("cannot access config")
)

// -- User Errors Declarations --
var (
	ErrInvalidEmail       = errors.New("invalid email format")
	ErrPasswordTooShort   = errors.New("password must be at least 8 characters")
	ErrPasswordTooWeak    = errors.New("password must contain uppercase, lowercase, number, and special character")
	ErrUserAlreadyExists  = errors.New("user with this email already exists")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrUserInactive       = errors.New("user account is inactive")
	ErrEmailNotConfirmed  = errors.New("email address not confirmed")
	ErrDatabaseError      = errors.New("database operation failed")
	ErrPasswordHashError  = errors.New("failed to hash password")
	ErrPasswordReset      = errors.New("failed to reset password")
)

// -- Token Errors Declarations --
var (
	ErrInvalidToken      = errors.New("invalid token")
	ErrTokenExpired      = errors.New("token has expired")
	ErrTokenRevoked      = errors.New("token has been revoked")
	ErrTokenInvalid      = errors.New("token has been already used or not found")
	ErrTokenGeneration   = errors.New("failed to generate token")
	ErrTokenVerification = errors.New("failed to verify token")
	ErrTokenIsEmpty      = errors.New("token is empty")
)
