package utils

import (
	"strings"
	"testing"
)

func TestSensitiveDataMasker_DefaultRules(t *testing.T) {
	masker := NewSensitiveDataMasker()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "OpenAI API Key",
			input:    "Here is my API key: sk-1234567890abcdefg1234567890abcdefg",
			expected: "Here is my API key: sk-***MASKED_OPENAI_KEY***",
		},
		{
			name:     "Anthropic API Key",
			input:    "Here is my Anthropic API key: sk-ant-api1234567890abcdefg",
			expected: "Here is my Anthropic API key: sk-ant-***MASKED_ANTHROPIC_KEY***",
		},
		{
			name:     "Bearer Token",
			input:    "Authorization: Bearer abcdefg12345==",
			expected: "Bearer ***MASKED_TOKEN***",
		},
		{
			name:     "Password in field",
			input:    `"password": "secretpassword123"`,
			expected: `"password": "***MASKED_PASSWORD***"`,
		},
		{
			name:     "Database URL",
			input:    "postgres://user:password@localhost:5432/mydb",
			expected: "postgres://user:***MASKED_DB_PASSWORD***@localhost:5432/mydb",
		},
		{
			name:     "Normal text without sensitive info",
			input:    "This is a normal sentence without sensitive data",
			expected: "This is a normal sentence without sensitive data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := masker.MaskString(tt.input)
			if result != tt.expected {
				t.Errorf("MaskString() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestSensitiveDataMasker_CustomRules(t *testing.T) {
	masker := NewSensitiveDataMasker()

	err := masker.AddRegexRule(
		"custom_test_rule",
		`secret_\w+`,
		`***MASKED_CUSTOM***`,
		"Test custom secret format",
	)
	if err != nil {
		t.Fatalf("Failed to add custom rule: %v", err)
	}

	input := "This contains secret_value that should be masked"
	expected := "This contains ***MASKED_CUSTOM*** that should be masked"
	result := masker.MaskString(input)

	if result != expected {
		t.Errorf("MaskString() = %v, want %v", result, expected)
	}
}

func TestMaskFields(t *testing.T) {
	masker := NewSensitiveDataMasker()

	fields := map[string]interface{}{
		"api_key": "sk-1234567890abcdefg1234567890abcdefg",
		"token":   "Bearer abcdefg12345==",
		"normal":  "normal_value",
		"nested_map": map[string]interface{}{
			"password": "secret123",
			"url":      "postgres://user:pass@localhost:5432/db",
		},
	}

	masked := masker.MaskFields(fields)

	// Verify basic field masking
	if apiKeyValue, ok := masked["api_key"].(string); !ok || apiKeyValue != "sk-***MASKED_OPENAI_KEY***" {
		t.Errorf("MaskFields()[api_key] = %v, want %v", masked["api_key"], "sk-***MASKED_OPENAI_KEY***")
	}

	if tokenValue, ok := masked["token"].(string); !ok || tokenValue != "Bearer ***MASKED_TOKEN***" {
		t.Errorf("MaskFields()[token] = %v, want %v", masked["token"], "Bearer ***MASKED_TOKEN***")
	}

	// Verify normal fields are untouched
	if normalValue, ok := masked["normal"].(string); !ok || normalValue != "normal_value" {
		t.Errorf("MaskFields()[normal] = %v, want %v", masked["normal"], "normal_value")
	}
}

func TestSensitiveDataDetection(t *testing.T) {
	masker := NewSensitiveDataMasker()

	// Test detection
	textWithSensitive := "Here is my API key: sk-1234567890abcdefg"
	textWithoutSensitive := "This is just normal text"

	if !masker.ContainsSensitiveData(textWithSensitive) {
		t.Error("ContainsSensitiveData() should return true for text containing sensitive data")
	}

	if masker.ContainsSensitiveData(textWithoutSensitive) {
		t.Error("ContainsSensitiveData() should return false for text without sensitive data")
	}

	// Test indicators
	indicators := masker.GetSensitiveIndicators("Multiple sk-123456 and secret=abcd1234 in this text")
	if len(indicators) == 0 {
		t.Error("GetSensitiveIndicators() should find indicators in the text")
	}
}

func TestConfigurableMasker(t *testing.T) {
	cfg := &SensitiveDataMaskConfig{
		Enabled: true,
		Rules: []SensitiveRuleConfig{
			{
				Name:        "test_custom_rule",
				Pattern:     `CUSTOM_\w+`,
				Replacement: "MASKED_CUSTOM",
				Description: "Custom rule test",
				Enabled:     true,
			},
		},
	}

	configMasker := NewConfigurableSensitiveMasker(cfg)

	result := configMasker.MaskString("Found CUSTOM_token and sk-api123 in text")

	if result != "Found MASKED_CUSTOM and sk-***MASKED_OPENAI_KEY*** in text" {
		t.Errorf("ConfigurableSensitiveMasker.MaskString() = %v", result)
	}
}

func TestMaskInterface(t *testing.T) {
	masker := NewSensitiveDataMasker()

	input := map[string]interface{}{
		"api_key": "sk-test1234567890",
		"items":   []interface{}{"normal", "sk-secret1234", "text"},
		"nested": map[string]interface{}{
			"token": "Bearer abcdefg123",
		},
	}

	output := masker.MaskInterface(input)

	processed, ok := output.(map[string]interface{})
	if !ok {
		t.Fatal("Result is not a map")
	}

	// Check that api_key was masked
	if apiKey, exists := processed["api_key"]; !exists || apiKey != "sk-***MASKED_OPENAI_KEY***" {
		t.Errorf("Expected masked API key, got %v", apiKey)
	}

	// Check that list was processed
	if items, exists := processed["items"]; exists {
		itemList, ok := items.([]interface{})
		if !ok {
			t.Error("Items is not a slice")
		} else if len(itemList) > 1 && itemList[1] != "sk-***MASKED_OPENAI_KEY***" {
			t.Errorf("Expected masked key in list, got %v", itemList[1])
		}
	}
}
