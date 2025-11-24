package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"

	"goauth/internal/constants"
	"goauth/internal/failure"
	"goauth/internal/logger"
	"goauth/internal/store/pg/migrations"
	"goauth/internal/store/pg/repository"
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

type Store struct {
	*repository.Queries
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{
		db:      db,
		Queries: repository.New(db),
	}
}

func (store *Store) ExecTx(ctx context.Context, fn func(*repository.Queries) error) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	q := repository.New(tx)
	err = fn(q)
	if err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("tx err: %v, rb err: %v", err, rbErr)
		}
		return err
	}

	return tx.Commit()
}
