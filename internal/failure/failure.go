package failure

import (
	"fmt"
	"goauth/internal/logger"
)

type Failure struct {
	Code    int
	Message string
	Err     error
}

func (e Failure) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e Failure) WithErr(err error) Failure {
	return Failure{
		Code:    e.Code,
		Message: e.Message,
		Err:     err,
	}
}

func (e Failure) LogFatal() {
	event := logger.Fatal().Int("code", e.Code)
	if e.Err != nil {
		event = event.Err(e.Err)
	}
	event.Msg(e.Message)
}

func (err Failure) Log() {
	logger.Info().Int("code", err.Code).Msg(err.Message)
}

func (err Failure) Warn() {
	logger.Warn().Int("code", err.Code).Msg(err.Message)
}

func (e Failure) LogError() {
	event := logger.Error().Int("code", e.Code)
	if e.Err != nil {
		event = event.Err(e.Err)
	}
	event.Msg(e.Message)
}
