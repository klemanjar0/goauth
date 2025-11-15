package store

import (
	"os"

	"goauth/internal/constants"
	"goauth/internal/failure"
	_ "goauth/internal/store/migrations"
)

func InitializeDB() {
	dbConnString := os.Getenv(constants.DBConnEnv)

	if dbConnString == "" {
		failure.EnvironmentVariableError.LogFatal()
	}

	//migrations.RunMigrations(db)
}
