// Package database -
package database

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rohit-Jung/search-engine/config"
)

func New(cfg *config.Config) (*pgxpool.Pool, error) {
	hostPort := net.JoinHostPort(cfg.Database.Host, strconv.Itoa(cfg.Database.Port))

	dbURL := fmt.Sprintf("postgres://%s:%s@%s/%s",
		cfg.Database.User,
		url.QueryEscape(cfg.Database.Password),
		hostPort,
		cfg.Database.Name,
	)

	// maintain a multiple connection pool, (not necessary for the project but good practice)
	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create pool: %w", err)
	}

	return pool, nil
}
