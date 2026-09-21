// Package database owns PostgreSQL connection setup for the API process.
package database

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NewPostgres creates and verifies the connection pool before the HTTP server starts.
func NewPostgres(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}
