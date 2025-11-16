package logger

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var Logger zerolog.Logger

func Init(isDevelopment bool) {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	if isDevelopment {
		output := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
		Logger = zerolog.New(output).With().Timestamp().Caller().Logger()
	} else {
		Logger = zerolog.New(os.Stdout).With().Timestamp().Caller().Logger()
	}

	log.Logger = Logger
}

func Debug() *zerolog.Event {
	return Logger.Debug()
}

func Info() *zerolog.Event {
	return Logger.Info()
}

func Warn() *zerolog.Event {
	return Logger.Warn()
}

func Error() *zerolog.Event {
	return Logger.Error()
}

func Fatal() *zerolog.Event {
	return Logger.Fatal()
}
