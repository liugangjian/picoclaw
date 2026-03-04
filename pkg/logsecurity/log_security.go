package logsecurity

import (
	"github.com/sipeed/picoclaw/pkg/logger"
	"github.com/sipeed/picoclaw/pkg/security"
)

var globalMasker *security.SensitiveDataMasker

// InitSecurityLayer initializes the security layer for logging by injecting sanitization functions
func InitSecurityLayer() {
	globalMasker = security.NewSensitiveDataMasker()

	// Inject sanitization methods into the logger
	logger.SetSanitizer(
		func(msg string) string {
			return globalMasker.MaskString(msg)
		},
		func(fields map[string]interface{}) map[string]interface{} {
			return globalMasker.MaskFields(fields)
		},
	)
}

// AddCustomRule adds a custom masking rule to the global masker
func AddCustomRule(name, pattern, replacement, description string) error {
	if globalMasker == nil {
		InitSecurityLayer()
	}
	return globalMasker.AddRegexRule(name, pattern, replacement, description)
}

// MaskString applies all configured masking rules to a string
func MaskString(input string) string {
	if globalMasker == nil {
		InitSecurityLayer()
	}
	return globalMasker.MaskString(input)
}

// MaskFields applies masking to map fields
func MaskFields(fields map[string]interface{}) map[string]interface{} {
	if globalMasker == nil {
		InitSecurityLayer()
	}
	return globalMasker.MaskFields(fields)
}

// ContainsSensitiveData checks if a string contains sensitive information
func ContainsSensitiveData(input string) bool {
	if globalMasker == nil {
		InitSecurityLayer()
	}
	return globalMasker.ContainsSensitiveData(input)
}
