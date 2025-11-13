package main

import (
	"log"
	"os"

	"github.com/joho/godotenv"
	"goauth/internal/logger"
)

func init() {
	if os.Getenv("ENV") != "production" {
		if err := godotenv.Load(); err != nil {
			log.Println("no .env file found, using system environment variables")
		}
	}
}

func main() {
	logger.Init(os.Getenv("ENV"))
	logger.Info().Msg("Starting auth service.")

}
