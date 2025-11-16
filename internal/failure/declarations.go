package failure

// -- Errors Declarations --
var (
	EnvironmentVariableError = Failure{
		Code:    0xE001,
		Message: "environment variable missing",
	}
	EnvironmentLocalFileError = Failure{
		Code:    0xE002,
		Message: "no .env file found, using system environment variables",
	}
	EnvironmentDatabaseError = Failure{
		Code:    0xE003,
		Message: "no database connection string found",
	}
	EnvironmentPortError = Failure{
		Code:    0xE004,
		Message: "port env variable is missing. applying default port 8080",
	}
	DatabaseInitializationError = Failure{
		Code:    0xE005,
		Message: "database failed to init",
	}
	DatabaseMigrationError = Failure{
		Code:    0xE006,
		Message: "database failed to run migrations",
	}
	FailedToStartServerError = Failure{
		Code:    0xE007,
		Message: "server failed to start",
	}
	ForcedShutdownServerError = Failure{
		Code:    0xE007,
		Message: "server forced to shutdown",
	}
)
