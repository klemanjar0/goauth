package store

import (
	"database/sql"
	"os"

	"goauth/internal/constants"
	"goauth/internal/failure"
	"goauth/internal/logger"
	"goauth/internal/store/pg/migrations"
)

func InitializeDB() *sql.DB {
	dbConnString := os.Getenv(constants.DB_CONN)

	if dbConnString == "" {
		code, msg := failure.EnvironmentDatabaseError.Get()
		logger.Fatal().Int("code", code).Msg(msg)
	}

	db, err := sql.Open("postgres", dbConnString)
	if err != nil {
		code, msg := failure.DatabaseInitializationError.Get()
		logger.Fatal().Err(err).Int("code", code).Msg(msg)

	}

	if err := migrations.RunMigrations(db); err != nil {
		code, msg := failure.DatabaseMigrationError.Get()
		logger.Fatal().Err(err).Int("code", code).Msg(msg)
	}

	return db
}
