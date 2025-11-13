package main

import (
	"os"

	"goauth/internal/constants"

	"github.com/joho/godotenv"
	"goauth/internal/logger"
)

func init() {
	if os.Getenv(constants.ENV) == constants.DEVELOPMENT {
		if err := godotenv.Load(); err != nil {
			constants.EnvironmentLocalFileError.Log(logger.Warn())
		}
	}
}

func main() {
	logger.Init(os.Getenv(constants.ENV))
	logger.Info().Msg("Starting auth service.")

}
