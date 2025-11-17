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
		msg := failure.ErrEnvironmentDatabase.Error()
		logger.Fatal().Msg(msg)
	}

	db, err := sql.Open("postgres", dbConnString)
	if err != nil {
		logger.Fatal().Err(err).Msg(failure.ErrDatabaseInitialization.Error())

	}

	if err := migrations.RunMigrations(db); err != nil {
		logger.Fatal().Err(err).Msg(failure.ErrDatabaseMigration.Error())
	}

	return db
}
