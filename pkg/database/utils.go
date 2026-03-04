// Package database provides utilities for database connection pool management.
package database

import (
	"context"
	"database/sql"
	"time"
)

// ConnectionMetrics collects usage metrics about a particular connection
type ConnectionMetrics struct {
	ConnectionID      string
	CreatedAt         time.Time
	LastUsedAt        time.Time
	QueriesExecuted   int64
	ErrorsEncountered int64
	Active            bool
}

// GlobalMonitor holds global state for monitoring all database pools
var GlobalMonitor *Monitor

// InitializeGlobalMonitor creates the global monitor singleton
func InitializeGlobalMonitor() error {
	if GlobalMonitor != nil {
		return nil // Already initialized
	}

	GlobalMonitor = NewMonitor()
	return nil
}

// WithTransaction wraps a function with automatic transaction start and rollback on error
func WithTransaction(ctx context.Context, pool Pool, opts *sql.TxOptions, fn func(*sql.Tx) error) error {
	tx, err := pool.BeginTx(ctx, opts)
	if err != nil {
		return err
	}

	defer func() {
		if p := recover(); p != nil {
			// Rollback in case of panic
			tx.Rollback()
			panic(p)
		}
	}()

	if err := fn(tx); err != nil {
		// Rollback in case of error
		tx.Rollback()
		return err
	}

	// Commit on success
	return tx.Commit()
}

// ExecWithRetry executes a query with retry logic
func ExecWithRetry(pool Pool, query string, args ...interface{}) (sql.Result, error) {
	return execWithRetry(pool, query, 3, args...) // Try up to 3 times
}

// execWithRetry performs an exec command with retry capability
func execWithRetry(pool Pool, query string, maxRetries int, args ...interface{}) (sql.Result, error) {
	var result sql.Result
	var err error

	for i := 0; i < maxRetries; i++ {
		result, err = pool.Exec(query, args...)
		if err == nil {
			return result, nil // Success
		}

		// Don't retry on context cancellation
		if err.Error() == "context canceled" {
			return result, err
		}

		// Simple exponential backoff: 100ms, 200ms, 400ms etc.
		time.Sleep(time.Duration(i+1) * 100 * time.Millisecond)
	}

	return result, err
}

// QueryWithRetry executes a query with retry logic
func QueryWithRetry(pool Pool, query string, args ...interface{}) (*sql.Rows, error) {
	return queryWithRetry(pool, query, 3, args...) // Try up to 3 times
}

// queryWithRetry performs a query command with retry capability
func queryWithRetry(pool Pool, query string, maxRetries int, args ...interface{}) (*sql.Rows, error) {
	var result *sql.Rows
	var err error

	for i := 0; i < maxRetries; i++ {
		result, err = pool.Query(query, args...)
		if err == nil {
			return result, nil // Success
		}

		// Don't retry on context cancellation
		if err.Error() == "context canceled" {
			return result, err
		}

		// Simple exponential backoff
		time.Sleep(time.Duration(i+1) * 100 * time.Millisecond)
	}

	return result, err
}

// CloseQuietly closes a pool without returning error
func CloseQuietly(pool Pool) {
	if pool != nil {
		pool.Close()
	}
}

// GetDefaultConfig returns a sensible default configuration for a database pool
func GetDefaultConfig(driverName, dataSourceName string) Config {
	return Config{
		DriverName:         driverName,
		DataSourceName:     dataSourceName,
		MaxOpenConns:       10,
		MaxIdleConns:       5,
		ConnMaxLifetime:    1 * time.Hour,
		ConnMaxIdleTime:    30 * time.Minute,
		ConnLifetimeJitter: 5 * time.Minute, // Add some randomness to avoid coordinated timeouts
	}
}

// GetSQLiteConfig returns a configuration optimized for SQLite usage
func GetSQLiteConfig(dataSourceName string) Config {
	cfg := GetDefaultConfig("sqlite", dataSourceName)

	// SQLite optimizations - for embedded scenarios like WhatsApp native
	cfg.MaxOpenConns = 1 // SQLite performs poorly with concurrent writers
	cfg.MaxIdleConns = 1
	cfg.ConnMaxLifetime = 24 * time.Hour // SQLite connections are lightweight
	cfg.ConnMaxIdleTime = 1 * time.Hour

	return cfg
}

// WaitUntilReady polls the database until it becomes available
func WaitUntilReady(ctx context.Context, pool Pool, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Try immediately first
	if err := pool.Ping(ctx); err == nil {
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := pool.Ping(ctx); err == nil {
				return nil // Ready
			}
			// Continue waiting if ping fails
		}
	}
}
