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
		{
			name:     "Simple YAML target key",
			input:    `The database name is base64://ZGF0YWJhc2U6IG15X2RiCg==//database`, // database: my_db encoded
			expected: "The database name is my_db",
		},
		{
			name:     "Simple JSON target key",
			input:    `The API key is base64://eyJhY2Nlc3NfdG9rZW4iOiAiMTIzNDUifQ==//access_token`, // {"access_token": "12345"} encoded
			expected: "The API key is 12345",
		},
		{
			name:     "Cached JSON target key",
			input:    `The base64://eyJmb28iOiAiZmlyZSIsICJiYXIiOiAiaWNlIn0=//foo and base64://eyJmb28iOiAiZmlyZSIsICJiYXIiOiAiaWNlIn0=//bar!`, // {"foo": "fire", "bar": "ice"} encoded
			expected: "The fire and ice!",
		},
	  {
			name: "Simple multiline replacement",
			input: `This is a multiline string.
The secret value is:
base64://aGVsbG8gd29ybGQK
`,
			expected: `This is a multiline string.
The secret value is:
hello world
`,
		},
		{
			name:     "Base64 encoder",
			input:    "The secret is base64://dXNlcjogYWRtMW4=//base64",
			expected: "The secret is dXNlcjogYWRtMW4=",
		},
		{
			name:     "YAML target key and base64 encoder",
			input:    "The secret is base64://dXNlcjogYWRtMW4=//user//base64",
			expected: "The secret is YWRtMW4=",
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
