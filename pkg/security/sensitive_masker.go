package security

import (
	"regexp"
	"strings"
)

// SensitiveDataMasker handles sensitive data detection and masking
type SensitiveDataMasker struct {
	rules []*MaskRule
}

// MaskRule defines a rule for detecting and masking sensitive data
type MaskRule struct {
	Name        string
	Pattern     *regexp.Regexp
	Replacement string
	Description string
}

// NewSensitiveDataMasker creates a new sensitive data masker with default rules
func NewSensitiveDataMasker() *SensitiveDataMasker {
	masker := &SensitiveDataMasker{
		rules: []*MaskRule{},
	}

	// Add default sensitive data detection rules
	masker.AddDefaultRules()

	return masker
}

// AddDefaultRules adds commonly used sensitive data detection rules
func (sm *SensitiveDataMasker) AddDefaultRules() {
	// API Key patterns
	sm.AddRule(&MaskRule{
		Name:        "apiKey",
		Pattern:     regexp.MustCompile(`(?i)(api[_-]?key|token|secret|password|pwd)\s*[=:]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?`),
		Replacement: `***MASKED_API_KEY***`,
		Description: "Matches common API key patterns",
	})

	// OAuth/Bearer tokens - Simplify pattern to match 'Bearer TOKEN'
	sm.AddRule(&MaskRule{
		Name:        "bearerToken",
		Pattern:     regexp.MustCompile(`(?i)(\bbearer\s+[A-Za-z0-9\._\-]{8,})`),
		Replacement: `Bearer ***MASKED_TOKEN***`,
		Description: "Matches OAuth bearer tokens",
	})

	// Authorization headers with tokens
	sm.AddRule(&MaskRule{
		Name:        "authorization",
		Pattern:     regexp.MustCompile(`(?i)(authorization\s*:\s*(bearer|basic|api-key)\s+[A-Za-z0-9\._\-]+=*)`),
		Replacement: `Authorization: ***MASKED_HEADER***`,
		Description: "Matches various authorization headers",
	})

	// Specific API key formats
	sm.AddRule(&MaskRule{
		Name:        "openaiKey",
		Pattern:     regexp.MustCompile(`(sk-[A-Za-z0-9_-]{32,64})`),
		Replacement: `sk-***MASKED_OPENAI_KEY***`,
		Description: "Matches OpenAI API key format",
	})

	sm.AddRule(&MaskRule{
		Name:        "anthropicKey",
		Pattern:     regexp.MustCompile(`(sk-ant-[A-Za-z0-9_-]{32,256})`),
		Replacement: `sk-ant-***MASKED_ANTHROPIC_KEY***`,
		Description: "Matches Anthropic API key format",
	})

	sm.AddRule(&MaskRule{
		Name:        "genericKey",
		Pattern:     regexp.MustCompile(`[A-Za-z0-9]{32,}[A-Za-z0-9_=\-\+\.]*`),
		Replacement: `***MASKED_GENERIC_KEY***`,
		Description: "Matches generic long hexadecimal-like keys",
	})

	// Password patterns in JSON/struct
	sm.AddRule(&MaskRule{
		Name:        "password",
		Pattern:     regexp.MustCompile(`(?i)("password"|"pwd"|"pass"|password|pwd|pass)\s*[:=]\s*"?([^",}\s]{4,}[^",}]*)"?`),
		Replacement: `$1: "***MASKED_PASSWORD***"`,
		Description: "Matches passwords in JSON/config structures",
	})

	// Database connection information
	sm.AddRule(&MaskRule{
		Name:        "databaseURL",
		Pattern:     regexp.MustCompile(`([a-zA-Z+.-]+)://(\w+):([^@]+)@([\w\.-]+):?(\d+)?(/[^\s?]*)?(\?[^\s]*)?`),
		Replacement: `${1}://$2:***MASKED_DB_PASSWORD***@$4:$5$6$7`,
		Description: "Matches database URLs with credentials",
	})
}

// AddRule adds a custom masking rule
func (sm *SensitiveDataMasker) AddRule(rule *MaskRule) {
	sm.rules = append(sm.rules, rule)
}

// MaskString applies all configured masking rules to a string
func (sm *SensitiveDataMasker) MaskString(input string) string {
	result := input
	for _, rule := range sm.rules {
		result = rule.Pattern.ReplaceAllString(result, rule.Replacement)
	}
	return result
}

// MaskFields applies masking to map fields
func (sm *SensitiveDataMasker) MaskFields(fields map[string]interface{}) map[string]interface{} {
	if fields == nil {
		return fields
	}

	masked := make(map[string]interface{})
	for k, v := range fields {
		switch val := v.(type) {
		case string:
			masked[k] = sm.MaskString(val)
		case map[string]interface{}:
			masked[k] = sm.MaskFields(val)
		case []interface{}:
			masked[k] = sm.maskSlice(val)
		default:
			masked[k] = v
		}
	}
	return masked
}

// maskSlice processes slices by recursively masking their elements
func (sm *SensitiveDataMasker) maskSlice(input []interface{}) []interface{} {
	if input == nil {
		return input
	}

	result := make([]interface{}, len(input))
	for i, v := range input {
		switch val := v.(type) {
		case string:
			result[i] = sm.MaskString(val)
		case map[string]interface{}:
			result[i] = sm.MaskFields(val)
		case []interface{}:
			result[i] = sm.maskSlice(val)
		default:
			result[i] = v
		}
	}
	return result
}

// ContainsSensitiveData checks if a string contains sensitive information
func (sm *SensitiveDataMasker) ContainsSensitiveData(input string) bool {
	for _, rule := range sm.rules {
		if rule.Pattern.MatchString(input) {
			return true
		}
	}
	return false
}

// GetSensitiveIndicators returns a list of detected sensitive indicators in the text
func (sm *SensitiveDataMasker) GetSensitiveIndicators(input string) []string {
	var indicators []string
	processed := make(map[string]bool)

	for _, rule := range sm.rules {
		matches := rule.Pattern.FindAllString(input, -1)
		for _, match := range matches {
			cleanMatch := strings.TrimSpace(match)
			if !processed[cleanMatch] {
				indicators = append(indicators, cleanMatch)
				processed[cleanMatch] = true
			}
		}
	}

	return indicators
}

// AddRegexRule adds a custom regex rule to the masker
func (sm *SensitiveDataMasker) AddRegexRule(name, pattern, replacement, description string) error {
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	rule := &MaskRule{
		Name:        name,
		Pattern:     compiled,
		Replacement: replacement,
		Description: description,
	}

	sm.AddRule(rule)
	return nil
}
