package migrations

import (
	"database/sql"
	"embed"
	"goauth/internal/logger"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/golang-migrate/migrate/v4/source/iofs"

	_ "github.com/lib/pq"
)

//go:embed queries/*.sql
var migrationsFS embed.FS

func RunMigrations(db *sql.DB) error {
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		logger.Debug().Err(err).Msg("postgres.WithInstance(db, &postgres.Config{})")
		return err
	}

	d, err := iofs.New(migrationsFS, "queries")
	if err != nil {
		logger.Debug().Err(err).Msg("iofs.New(migrationsFS, queries)")
		return err
	}

	m, err := migrate.NewWithInstance("iofs", d, "postgres", driver)
	if err != nil {
		logger.Debug().Msg("migrate.NewWithInstance(iofs, d, postgres, driver)")
		return err
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		logger.Debug().Msg("m.Up()")
		return err
	}

	logger.Info().Msg("Migrations applied successfully.")
	return nil
}
