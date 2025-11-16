package failure

// -- Errors Declarations --
var (
	EnvironmentVariableError = &Failure{
		Code:    0x0001,
		Message: "environment variable missing",
	}
	EnvironmentLocalFileError = &Failure{
		Code:    0x0002,
		Message: "no .env file found, using system environment variables",
	}
	EnvironmentDatabaseError = &Failure{
		Code:    0x0003,
		Message: "no database connection string found",
	}
	EnvironmentPortError = &Failure{
		Code:    0x0004,
		Message: "port env variable is missing. applying default port 8080",
	}
	DatabaseInitializationError = &Failure{
		Code:    0x0005,
		Message: "database failed to init",
	}
	DatabaseMigrationError = &Failure{
		Code:    0x0006,
		Message: "database failed to run migrations",
	}
	FailedToStartServerError = &Failure{
		Code:    0x0007,
		Message: "server failed to start",
	}
	ForcedShutdownServerError = &Failure{
		Code:    0x0008,
		Message: "server forced to shutdown",
	}
	RedisClientError = &Failure{
		Code:    0x0009,
		Message: "failed to connect to redis",
	}
)
