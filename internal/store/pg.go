package store

import (
	"os"

	"goauth/internal/constants"
	"goauth/internal/logger"
	_ "goauth/internal/store/migrations"
)

func InitializeDB() {
	dbConnString := os.Getenv(constants.DBConnEnv)

	if dbConnString == "" {
		constants.EnvironmentVariableError.Log(logger.Fatal())
	}

	//migrations.RunMigrations(db)
}
