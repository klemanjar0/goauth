package constants

import "github.com/rs/zerolog"

type ServiceError struct {
	Code        int
	Description string
}

func (err ServiceError) Error() string {
	return err.Description
}

func (err ServiceError) Log(logger *zerolog.Event) {
	logger.Int("code", err.Code).Msg(err.Description)
}

// -- Errors Declarations --
var (
	EnvironmentVariableError = ServiceError{
		Code:        0x0001,
		Description: "Environment variable missing.",
	}
	EnvironmentLocalFileError = ServiceError{
		Code:        0x0002,
		Description: "No .env file found, using system environment variables.",
	}
)
