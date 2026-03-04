package utils

import (
	"fmt"
	"regexp"
	"strings"
)

// SensitiveRuleConfig defines a rule for sensitive data detection for masking
type SensitiveRuleConfig struct {
	Name        string
	Pattern     string
	Replacement string
	Description string
	Enabled     bool
}

// SensitiveDataMaskConfig holds configuration for sensitive data masking
type SensitiveDataMaskConfig struct {
	Enabled bool
	Rules   []SensitiveRuleConfig
}

// ConfigurableSensitiveMasker extends SensitiveDataMasker with config-based rules
type ConfigurableSensitiveMasker struct {
	*SensitiveDataMasker
	config *SensitiveDataMaskConfig
}

// NewDefaultSensitiveDataMaskConfig returns default configuration
func NewDefaultSensitiveDataMaskConfig() SensitiveDataMaskConfig {
	return SensitiveDataMaskConfig{
		Enabled: true,
		Rules:   []SensitiveRuleConfig{},
	}
}

// NewConfigurableSensitiveMasker creates a new configurable sensitive data masker
func NewConfigurableSensitiveMasker(config *SensitiveDataMaskConfig) *ConfigurableSensitiveMasker {
	masker := &ConfigurableSensitiveMasker{
		SensitiveDataMasker: NewSensitiveDataMasker(),
		config:              config,
	}

	if config != nil && config.Enabled {
		masker.loadConfigRules()
	}

	return masker
}

// loadConfigRules loads custom rules from configuration
func (cm *ConfigurableSensitiveMasker) loadConfigRules() {
	if cm.config == nil {
		return
	}

	for _, rule := range cm.config.Rules {
		if rule.Enabled {
			err := cm.AddRegexRule(rule.Name, rule.Pattern, rule.Replacement, rule.Description)
			if err != nil {
				fmt.Printf("Warning: Failed to add custom sensitive data rule %s: %v\n", rule.Name, err)
			}
		}
	}
}

// UpdateConfig updates the configuration and reloads rules
func (cm *ConfigurableSensitiveMasker) UpdateConfig(config *SensitiveDataMaskConfig) {
	cm.config = config
	// Keep default rules and add new ones
	cm.SensitiveDataMasker = NewSensitiveDataMasker() // Reset to default rules first
	cm.loadConfigRules()
}

// GetEnabledStatus returns whether sensitive data masking is enabled
func (cm *ConfigurableSensitiveMasker) GetEnabledStatus() bool {
	if cm.config == nil {
		return true // Default to enabled
	}
	return cm.config.Enabled
}

// GetActiveRules returns a list of currently active rules
func (cm *ConfigurableSensitiveMasker) GetActiveRules() []*MaskRule {
	return cm.rules
}

// ValidateRule validates whether a given rule pattern is a valid regex
func ValidateRule(pattern string) error {
	_, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid regex pattern: %w", err)
	}
	return nil
}
