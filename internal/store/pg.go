package store

import (
	"context"
	"fmt"
	"os"

	"goauth/internal/config"
	"goauth/internal/constants"
	"goauth/internal/failure"
	"goauth/internal/logger"
	"goauth/internal/store/pg/migrations"
	"goauth/internal/store/pg/repository"

	"github.com/jackc/pgx/v5/pgxpool"
)

func InitializeDB(ctx context.Context, cfg *config.Config) *pgxpool.Pool {
	pCfg := cfg.PoolConfig
	dbConnString := os.Getenv(constants.DB_CONN)

	if dbConnString == "" {
		msg := failure.ErrEnvironmentDatabase.Error()
		logger.Fatal().Msg(msg)
	}

	config, err := pgxpool.ParseConfig(dbConnString)

	if err != nil {
		logger.Fatal().Err(err).Msg(failure.ErrPoolConnection.Error())
		return nil
	}

	config.MaxConns = pCfg.MaxConns
	config.MinConns = pCfg.MinConns
	config.MaxConnLifetime = pCfg.MaxConnLifetime
	config.MaxConnIdleTime = pCfg.MaxConnIdleTime
	config.HealthCheckPeriod = pCfg.HealthCheckPeriod

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		logger.Fatal().Err(err).Msg(failure.ErrPoolCreate.Error())
		return nil
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil
	}

	if cfg.RunMigrationsOnStart {
		if err := migrations.RunMigrations(pool); err != nil {
			logger.Fatal().Err(err).Msg(failure.ErrDatabaseMigration.Error())
		}
	}

	return pool
}

type Store struct {
	*repository.Queries
	Pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{
		Pool:    pool,
		Queries: repository.New(pool),
	}
}

func (store *Store) ExecTx(ctx context.Context, fn func(*repository.Queries) error) error {
	tx, err := store.Pool.Begin(ctx)

	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	q := repository.New(tx)

	if err := fn(q); err != nil {
		if rbErr := tx.Rollback(ctx); rbErr != nil {
			return fmt.Errorf("tx err: %v, rb err: %v", err, rbErr)
		}
		return err
	}

	return tx.Commit(ctx)
}
