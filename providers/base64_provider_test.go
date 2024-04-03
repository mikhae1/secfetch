package providers_test

import (
	"context"
	"testing"

	"github.com/mikhae1/secfetch/providers" // Adjust the import path as needed
)

func TestBase64Provider(t *testing.T) {
	prefix := "base64://"
	provider := providers.NewBase64Provider(prefix)

	t.Run("GetSecretValue_Valid", func(t *testing.T) {
		encoded := "aGVsbG8gd29ybGQ=" // Base64 encoded "hello world"
		expected := "hello world"

		actual, err := provider.GetSecretValue(context.Background(), encoded)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if actual != expected {
			t.Errorf("Expected: %q, Actual: %q", expected, actual)
		}
	})

	t.Run("GetSecretValue_Invalid", func(t *testing.T) {
		invalid := "not-base64"

		_, err := provider.GetSecretValue(context.Background(), invalid)
		if err == nil {
			t.Error("Expected error for invalid Base64 string, but got nil")
		}
	})

	t.Run("GetPrefix", func(t *testing.T) {
		actual := provider.GetPrefix()
		if actual != prefix {
			t.Errorf("Expected prefix: %q, Actual: %q", prefix, actual)
		}
	})

	t.Run("GetRegex", func(t *testing.T) {
		regex := provider.GetRegex()
		expectedPattern := prefix + `([a-zA-Z0-9+/=]+)`

		if regex.String() != expectedPattern {
			t.Errorf("Expected regex pattern: %q, Actual: %q", expectedPattern, regex.String())
		}
	})
}
