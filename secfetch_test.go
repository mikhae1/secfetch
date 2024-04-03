package main

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/mikhae1/secfetch/providers"
)

func TestReplaceWithRegex_Base64Provider(t *testing.T) {
	provider := providers.NewBase64Provider("base64://")

	// Test cases
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Simple replacement",
			input:    "The secret is base64://aGVsbG8gd29ybGQ=", // "hello world" encoded
			expected: "The secret is hello world",
		},
		{
			name:     "Multiple replacements",
			input:    "Secret 1: base64://aGVsbG8=, Secret 2: base64://d29ybGQ=", // "hello" and "world" encoded
			expected: "Secret 1: hello, Secret 2: world",
		},
		{
			name:     "No replacement",
			input:    "No replacement should occur",
			expected: "No replacement should occur",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Call replaceWithRegex with a mock context
			ctx := context.Background()
			actual := replaceWithRegex(ctx, tc.input, provider)

			// Check if the output matches the expected string
			if !strings.Contains(actual, tc.expected) {
				t.Errorf("Expected output to contain: %q, Actual output: %q", tc.expected, actual)
			}
		})
	}
}

func TestReplaceWithRegex_EnvProvider(t *testing.T) {
	// Set up environment variables for testing
	os.Setenv("TEST_SECRET", "my_secret_value") // Set a test environment variable

	// Create an EnvProvider instance
	provider := providers.NewEnvProvider("env://")

	// Test cases
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Simple replacement",
			input:    "The secret is env://TEST_SECRET",
			expected: "The secret is my_secret_value",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Call replaceWithRegex with a mock context
			ctx := context.Background()
			actual := replaceWithRegex(ctx, tc.input, provider)

			// Check if the output matches the expected string
			if !strings.Contains(actual, tc.expected) {
				t.Errorf("Expected output to contain: %q, Actual output: %q", tc.expected, actual)
			}
		})
	}
}
