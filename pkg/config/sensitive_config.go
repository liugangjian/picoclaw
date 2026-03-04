package config

// SensitiveDataConfig holds configuration for sensitive data masking
type SensitiveDataConfig struct {
	Enabled bool            `json:"sensitive_data_masking_enabled" yaml:"sensitive_data_masking_enabled" env:"PICOCLAW_SENSITIVE_DATA_MASKING_ENABLED"`
	Rules   []SensitiveRule `json:"sensitive_rules" yaml:"sensitive_rules"`
}

// SensitiveRule defines a rule for sensitive data detection
type SensitiveRule struct {
	Name        string `json:"name" yaml:"name"`
	Pattern     string `json:"pattern" yaml:"pattern"`
	Replacement string `json:"replacement" yaml:"replacement"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	Enabled     bool   `json:"enabled" yaml:"enabled"`
}

// DefaultSensitiveDataConfig returns the default sensitive data configuration
func DefaultSensitiveDataConfig() SensitiveDataConfig {
	return SensitiveDataConfig{
		Enabled: true,
		Rules:   []SensitiveRule{},
	}
}
