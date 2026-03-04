package hotreload

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/sipeed/picoclaw/pkg/config"
)

// ConfigReloader manages hot reloading of configuration files.
type ConfigReloader struct {
	configPath string
	watcher    *fsnotify.Watcher
	callback   func(*config.Config) error
	config     *config.Config

	mu     sync.RWMutex
	stopCh chan struct{}
	doneCh chan struct{}
}

// NewConfigReloader creates a new configuration reloader for the given path.
func NewConfigReloader(configPath string) (*ConfigReloader, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	reloader := &ConfigReloader{
		configPath: configPath,
		watcher:    watcher,
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
	}

	err = reloader.watch()
	if err != nil {
		watcher.Close()
		return nil, fmt.Errorf("failed to watch configuration file: %w", err)
	}

	return reloader, nil
}

// SetCallback sets the callback function to be called when the configuration changes.
func (cr *ConfigReloader) SetCallback(callback func(*config.Config) error) {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	cr.callback = callback
}

// SetInitialConfig sets the initial configuration to be referenced during reloads.
func (cr *ConfigReloader) SetInitialConfig(cfg *config.Config) {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	cr.config = cfg
}

// watch adds the configuration file to the watcher.
func (cr *ConfigReloader) watch() error {
	absPath, err := filepath.Abs(cr.configPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	return cr.watcher.Add(absPath)
}

// Reload manually reloads the configuration file.
func (cr *ConfigReloader) Reload() error {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	if cr.config == nil {
		return fmt.Errorf("initial config not set, cannot reload")
	}

	newConfig, err := config.LoadConfig(cr.configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	*cr.config = *newConfig

	// Call the callback if set
	if cr.callback != nil {
		return cr.callback(newConfig)
	}

	return nil
}

// getEvent checks if a relevant file event occurred.
func (cr *ConfigReloader) getEvent(timeout time.Duration) (bool, fsnotify.Event, error) {
	select {
	case event, ok := <-cr.watcher.Events:
		if !ok {
			return false, fsnotify.Event{}, fmt.Errorf("watcher has closed")
		}

		// Check if the config file changed
		if filepath.Clean(event.Name) == filepath.Clean(cr.configPath) {
			// Filter to only write events (WRITE, CHMOD, CREATE) and RENAME/REMOVE to handle file replacement via atomic writes
			writeEvents := fsnotify.Write | fsnotify.Chmod | fsnotify.Create | fsnotify.Remove | fsnotify.Rename
			if event.Op&writeEvents != 0 {
				return true, event, nil
			}
		}
		return false, fsnotify.Event{}, nil

	case err, ok := <-cr.watcher.Errors:
		if !ok {
			return false, fsnotify.Event{}, fmt.Errorf("watcher has closed")
		}
		return false, fsnotify.Event{}, fmt.Errorf("watcher error: %w", err)

	case <-time.After(timeout):
		return false, fsnotify.Event{}, nil

	case <-cr.stopCh:
		return false, fsnotify.Event{}, fmt.Errorf("reloader stopped")
	}
}

// Watch watches the configuration file for changes and reloads it automatically.
// This method blocks until Stop() is called or an error occurs.
func (cr *ConfigReloader) Watch(ctx context.Context) error {
	debounceTimer := time.NewTimer(500 * time.Millisecond)
	if !debounceTimer.Stop() {
		<-debounceTimer.C
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-cr.stopCh:
			close(cr.doneCh)
			return nil

		default:
			hasEvent, _, err := cr.getEvent(100 * time.Millisecond)
			if err != nil {
				// If the reloader was stopped, return gracefully
				if err.Error() == "reloader stopped" {
					continue
				}
				return err
			}

			if hasEvent {
				// Restart debounce timer
				if !debounceTimer.Stop() {
					select {
					case <-debounceTimer.C:
					default:
					}
				}
				// Debounce for 500ms to handle multiple rapid file changes
				debounceTimer.Reset(500 * time.Millisecond)

				// Wait for debounce to finish
				select {
				case <-debounceTimer.C:
					if err := cr.Reload(); err != nil {
						log.Printf("Failed to reload config: %v", err)
						continue
					}
					log.Printf("Configuration reloaded successfully from %s", cr.configPath)

				case <-cr.stopCh:
					// Stop listening to events if stop was requested during debounce
					if !debounceTimer.Stop() {
						<-debounceTimer.C
					}
					close(cr.doneCh)
					return nil
				}
			}
		}
	}
}

// Stop stops the configuration reloader.
func (cr *ConfigReloader) Stop() error {
	close(cr.stopCh)

	// Close the watcher to stop watching files
	err := cr.watcher.Close()

	// Wait for Watch method to finish
	<-cr.doneCh

	return err
}
