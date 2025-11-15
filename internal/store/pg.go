package store

import (
	"database/sql"
	"os"

	"goauth/internal/constants"
	"goauth/internal/failure"
	"goauth/internal/store/pg/migrations"
)

func InitializeDB() *sql.DB {
	dbConnString := os.Getenv(constants.DBConnEnv)

	if dbConnString == "" {
		failure.EnvironmentDatabaseError.LogFatal()
	}

	db, dbErr := sql.Open("postgres", dbConnString)

	if dbErr != nil {
		failure.DatabaseInitializationError.WithErr(dbErr).LogFatal()
	}

	if err := migrations.RunMigrations(db); err != nil {
		failure.DatabaseMigrationError.WithErr(dbErr).LogFatal()
	}

	return db
}
