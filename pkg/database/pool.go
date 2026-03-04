// Package database provides database connection pooling capabilities for PicoClaw.
// It supports various database drivers with standardized connection management,
// monitoring, and timeout controls.
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Config defines the connection pool configuration options
type Config struct {
	DriverName         string
	DataSourceName     string
	MaxOpenConns       int           // Maximum number of open connections
	MaxIdleConns       int           // Maximum number of idle connections
	ConnMaxLifetime    time.Duration // Maximum lifetime of a connection
	ConnMaxIdleTime    time.Duration // Maximum idle time of a connection
	ConnLifetimeJitter time.Duration // Random jitter to avoid connection storms
}

// Validate ensures the config is valid
func (c *Config) Validate() error {
	if c.DriverName == "" {
		return errors.New("driver name cannot be empty")
	}
	if c.DataSourceName == "" {
		return errors.New("data source name cannot be empty")
	}

	if c.MaxOpenConns <= 0 {
		c.MaxOpenConns = 10 // Default value
	}
	if c.MaxIdleConns <= 0 {
		c.MaxIdleConns = 2 // Default value
	}
	if c.MaxIdleConns > c.MaxOpenConns {
		c.MaxIdleConns = c.MaxOpenConns
	}

	if c.ConnMaxLifetime == 0 {
		c.ConnMaxLifetime = 1 * time.Hour
	}
	if c.ConnMaxIdleTime == 0 {
		c.ConnMaxIdleTime = 30 * time.Minute
	}

	return nil
}

// Pool represents a database connection pool
type Pool interface {
	// Get retrieves a connection from the pool
	Get() (*sql.DB, error)

	// Stats returns connection pool statistics
	Stats() sql.DBStats

	// Ping checks if the pool is healthy
	Ping(ctx context.Context) error

	// Close closes all connections in the pool
	Close() error

	// Begin starts a transaction
	BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error)

	// Query executes a query that returns rows
	Query(query string, args ...interface{}) (*sql.Rows, error)

	// QueryRow executes a query that returns at most one row
	QueryRow(query string, args ...interface{}) *sql.Row

	// Exec executes a query without returning rows
	Exec(query string, args ...interface{}) (sql.Result, error)

	// Prepare creates a prepared statement
	Prepare(query string) (*sql.Stmt, error)
}

// pool implements the Pool interface
type pool struct {
	db     *sql.DB
	cfg    *Config
	mu     sync.RWMutex
	closed bool
}

// New creates a new database connection pool with the specified configuration
func New(cfg Config) (Pool, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	db, err := sql.Open(cfg.DriverName, cfg.DataSourceName)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure the connection pool
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	db.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)

	p := &pool{
		db:  db,
		cfg: &cfg,
	}

	// Test the connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := p.db.PingContext(ctx); err != nil {
		db.Close() // Clean up the failed connection
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return p, nil
}

// Get returns the underlying database connection pool
func (p *pool) Get() (*sql.DB, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.closed {
		return nil, errors.New("pool is closed")
	}

	return p.db, nil
}

// Stats returns statistics about the connection pool
func (p *pool) Stats() sql.DBStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.closed {
		return sql.DBStats{}
	}

	return p.db.Stats()
}

// Ping verifies connectivity to the database
func (p *pool) Ping(ctx context.Context) error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.closed {
		return errors.New("pool is closed")
	}

	return p.db.PingContext(ctx)
}

// Close closes all connections in the pool
func (p *pool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}

	p.closed = true
	return p.db.Close()
}

// BeginTx starts a transaction
func (p *pool) BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.closed {
		return nil, errors.New("pool is closed")
	}

	return p.db.BeginTx(ctx, opts)
}

// Query executes a query that returns rows
func (p *pool) Query(query string, args ...interface{}) (*sql.Rows, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.closed {
		return nil, errors.New("pool is closed")
	}

	return p.db.Query(query, args...)
}

// QueryRow executes a query that returns at most one row
func (p *pool) QueryRow(query string, args ...interface{}) *sql.Row {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.closed {
		return &sql.Row{} // Return empty row that will result in error when used
	}

	return p.db.QueryRow(query, args...)
}

// Exec executes a query without returning rows
func (p *pool) Exec(query string, args ...interface{}) (sql.Result, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.closed {
		return nil, errors.New("pool is closed")
	}

	return p.db.Exec(query, args...)
}

// Prepare creates a prepared statement
func (p *pool) Prepare(query string) (*sql.Stmt, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.closed {
		return nil, errors.New("pool is closed")
	}

	return p.db.Prepare(query)
}
