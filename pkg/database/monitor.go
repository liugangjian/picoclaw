// Package database provides monitoring capabilities for database connection pools.
package database

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"
)

// Monitor collects and reports connection pool metrics
type Monitor struct {
	pools map[string]Pool
	mu    sync.RWMutex
}

// NewMonitor creates a new database connection pool monitor
func NewMonitor() *Monitor {
	return &Monitor{
		pools: make(map[string]Pool),
	}
}

// Register adds a pool to be monitored
func (m *Monitor) Register(name string, pool Pool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.pools[name]; exists {
		return fmt.Errorf("pool with name %s already exists", name)
	}

	m.pools[name] = pool
	return nil
}

// Unregister removes a pool from monitoring
func (m *Monitor) Unregister(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.pools, name)
}

// GetPoolStats returns stats for a specific pool
func (m *Monitor) GetPoolStats(name string) (*ConnectionStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pool, exists := m.pools[name]
	if !exists {
		return nil, fmt.Errorf("pool %s not found", name)
	}

	dbStats := pool.Stats()
	return &ConnectionStats{
		Name:               name,
		MaxOpenConnections: dbStats.MaxOpenConnections,
		OpenConnections:    dbStats.OpenConnections,
		InUse:              dbStats.InUse,
		Idle:               dbStats.Idle,
		WaitCount:          dbStats.WaitCount,
		WaitDuration:       dbStats.WaitDuration,
		MaxIdleClosed:      dbStats.MaxIdleClosed,
		MaxIdleTimeClosed:  dbStats.MaxIdleTimeClosed,
		MaxLifetimeClosed:  dbStats.MaxLifetimeClosed,
	}, nil
}

// GetAllStats returns stats for all pools
func (m *Monitor) GetAllStats() ([]*ConnectionStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make([]*ConnectionStats, 0, len(m.pools))
	for name, pool := range m.pools {
		dbStats := pool.Stats()
		stats = append(stats, &ConnectionStats{
			Name:               name,
			MaxOpenConnections: dbStats.MaxOpenConnections,
			OpenConnections:    dbStats.OpenConnections,
			InUse:              dbStats.InUse,
			Idle:               dbStats.Idle,
			WaitCount:          dbStats.WaitCount,
			WaitDuration:       dbStats.WaitDuration,
			MaxIdleClosed:      dbStats.MaxIdleClosed,
			MaxIdleTimeClosed:  dbStats.MaxIdleTimeClosed,
			MaxLifetimeClosed:  dbStats.MaxLifetimeClosed,
		})
	}

	return stats, nil
}

// ConnectionStats holds detailed statistics about a connection pool
type ConnectionStats struct {
	Name string // Pool name

	// Standard database/db stats
	MaxOpenConnections int           // Maximum number of open connections to the database
	OpenConnections    int           // The number of established connections both in use and idle
	InUse              int           // The number of connections currently in use
	Idle               int           // The number of idle connections
	WaitCount          int64         // The total number of connections waited for
	WaitDuration       time.Duration // The total time blocked waiting for a new connection
	MaxIdleClosed      int64         // The total number of connections closed due to SetMaxIdleConns
	MaxIdleTimeClosed  int64         // The total number of connections closed due to SetConnMaxIdleTime
	MaxLifetimeClosed  int64         // The total number of connections closed due to SetConnMaxLifetime

	// Calculated metrics
	ConnectionUtilization float64 // Percentage of connections in use (inUse/maxOpenConnections)
	IdleUtilization       float64 // Percentage of idle connections (idle/maxOpenConnections)
	WaitRate              float64 // Average wait rate
}

// Healthy determines if the pool appears to be functioning properly
func (cs *ConnectionStats) Healthy() bool {
	// Consider unhealthy if there are excessive waits or connections are frequently closed due to timeouts
	return cs.WaitCount < 100 && // Less than 100 waits is generally good
		cs.MaxIdleTimeClosed < cs.OpenConnections && // Not constantly closing connections due to idle timeout
		cs.MaxLifetimeClosed < cs.OpenConnections // Not constantly closing connections due to lifetime
}

// HealthReport returns detailed health information
func (m *Monitor) HealthReport(ctx context.Context) (*HealthReport, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pools := make([]*HealthDetail, 0, len(m.pools))

	for name, pool := range m.pools {
		dbStats := pool.Stats()

		healthy := true
		var issues []string

		// Perform live health checks
		if err := pool.Ping(ctx); err != nil {
			healthy = false
			issues = append(issues, fmt.Sprintf("ping failed: %v", err))
		}

		if dbStats.OpenConnections == 0 {
			issues = append(issues, "no open connections")
		}

		// Check if utilization is good (< 80% in use considered healthy)
		if dbStats.MaxOpenConnections > 0 {
			utilization := float64(dbStats.InUse) / float64(dbStats.MaxOpenConnections)
			if utilization >= 0.8 {
				issues = append(issues, fmt.Sprintf("connection utilization high: %.2f%%", utilization*100))
			}
		}

		// Check if too many connections are being closed due to timeouts
		totalClosed := dbStats.MaxIdleTimeClosed + dbStats.MaxLifetimeClosed
		if totalClosed > dbStats.OpenConnections {
			issues = append(issues, "many connections are being closed due to timeouts")
		}

		detail := &HealthDetail{
			Name:    name,
			Healthy: healthy,
			Issues:  issues,
			Stats:   &dbStats,
		}
		pools = append(pools, detail)
	}

	report := &HealthReport{
		Timestamp: time.Now(),
		Pools:     pools,
		OverallHealthy: len(pools) == 0 || // No pools is fine initially
			func() bool {
				for _, pool := range pools {
					if !pool.Healthy {
						return false
					}
				}
				return true
			}(),
	}

	return report, nil
}

// HealthDetail contains health information for a specific pool
type HealthDetail struct {
	Name    string
	Healthy bool
	Issues  []string
	Stats   *sql.DBStats
}

// HealthReport contains comprehensive health information about all pools
type HealthReport struct {
	Timestamp      time.Time
	Pools          []*HealthDetail
	OverallHealthy bool
}

// String provides a formatted representation of the health report
func (hr *HealthReport) String() string {
	result := fmt.Sprintf("Database Health Report - %s\nOverall Status: %s\n\n",
		hr.Timestamp.Format(time.RFC3339),
		map[bool]string{true: "HEALTHY", false: "UNHEALTHY"}[hr.OverallHealthy])

	for _, pool := range hr.Pools {
		result += fmt.Sprintf("Pool: %s - Status: %s\n",
			pool.Name,
			map[bool]string{true: "HEALTHY", false: "ISSUES"}[pool.Healthy])

		for _, issue := range pool.Issues {
			result += fmt.Sprintf("  - Issue: %s\n", issue)
		}

		if pool.Stats != nil {
			stats := pool.Stats
			result += fmt.Sprintf("  - Connections: Open=%d InUse=%d Idle=%d MaxOpen=%d\n",
				stats.OpenConnections, stats.InUse, stats.Idle, stats.MaxOpenConnections)
		}
		result += "\n"
	}

	return result
}
