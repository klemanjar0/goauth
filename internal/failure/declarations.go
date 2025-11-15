package failure

// -- Errors Declarations --
var (
	EnvironmentVariableError = Failure{
		Code:    0x0001,
		Message: "Environment variable missing.",
	}
	EnvironmentLocalFileError = Failure{
		Code:    0x0002,
		Message: "No .env file found, using system environment variables.",
	}
)
