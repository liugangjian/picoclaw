package logsecurity

import (
	"testing"
)

func TestInitSecurityLayer(t *testing.T) {
	// Test the initialization without causing side effects
	InitSecurityLayer()

	// Test that sensitive data is masked
	testInput := "My API key is sk-proj-secret1234567890"
	masked := MaskString(testInput)

	if masked == testInput {
		t.Errorf("Sensitive data was not masked. Input: %s, Output: %s", testInput, masked)
	}

	// Confirm it's effectively masked
	if !ContainsSensitiveData(testInput) {
		t.Error("ContainsSensitiveData did not detect sensitive data when it should have")
	}
}

func TestAddCustomRule(t *testing.T) {
	InitSecurityLayer()

	// Add a custom rule
	err := AddCustomRule(
		"test_custom_rule",
		`TEST_\w+`,
		"MASKED_CUSTOM",
		"A test rule",
	)
	if err != nil {
		t.Fatalf("Failed to add custom rule: %v", err)
	}

	// Test that custom rule works
	result := MaskString("This has TEST_data that should be masked")
	if result != "This has MASKED_CUSTOM that should be masked" {
		t.Errorf("Custom rule did not work. Result: %s", result)
	}
}

func TestMaskFields(t *testing.T) {
	InitSecurityLayer()

	fields := map[string]interface{}{
		"api_key":      "sk-real-secret-key",
		"normal_field": "normal_value",
		"nested_map": map[string]interface{}{
			"token": "Bearer tokenabc123",
		},
	}

	masked := MaskFields(fields)

	// Verify sensitive field is masked
	if apiKey, ok := masked["api_key"]; !ok || apiKey != "sk-***MASKED_OPENAI_KEY***" {
		t.Errorf("API key was not masked properly: %v", apiKey)
	}

	// Verify normal field is not affected
	if normal, ok := masked["normal_field"]; !ok || normal != "normal_value" {
		t.Errorf("Normal field was incorrectly modified: %v", normal)
	}
}
