///usr/bin/true; exec /usr/bin/env go run "$0" "$@"

// The script reads input from stdin, scans for occurrences of the specified prefixes followed by the secret identifier,
// retrieves the corresponding secret value from the appropriate service, and replaces the placeholders in the input with the actual secret values.
// It supports:
// - "ssm://" AWS Parameters Store
// - "secrets://" AWS Secrets Manager
// - "env://" Environment Variables
// - "base64://" Base64 encoded strings (not safe)

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/ssm"

	"github.com/mikhae1/secfetch/providers"
)

var (
	ignoreErrors = os.Getenv("SEC_IGNORE_ERR") != ""
	retries, _   = strconv.Atoi(getEnv("SEC_RETRIES", "3"))
	timeout, _   = strconv.Atoi(getEnv("SEC_TIMEOUT", "30"))
	cache        sync.Map
)

func main() {
	awsSess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	ssmClient := ssm.New(awsSess)
	secretsClient := secretsmanager.New(awsSess)

	// Create SecretProvider instances for each service.
	ssmPrefix := getEnv("SEC_SSM_PREFIX", "ssm://")
	secretsPrefix := getEnv("SEC_SECRETS_PREFIX", "secrets://")
	envPrefix := getEnv("SEC_ENV_PREFIX", "env://")
	base64Prefix := getEnv("SEC_BASE64_PREFIX", "base64://")

	ssmProvider := providers.NewSSMProvider(ssmClient, ssmPrefix)
	secretsManagerProvider := providers.NewSecretsManagerProvider(secretsClient, secretsPrefix)
	envProvider := providers.NewEnvProvider(envPrefix)
	base64Provider := providers.NewBase64Provider(base64Prefix)

	providers := []providers.SecretProvider{ssmProvider, secretsManagerProvider, envProvider, base64Provider}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()

		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
		defer cancel()

		modifiedLine := line
		for _, provider := range providers {
			modifiedLine = replaceWithRegex(ctx, modifiedLine, provider)
		}

		fmt.Println(modifiedLine)

		if !ignoreErrors && scanner.Err() != nil {
			handleError(fmt.Errorf("Error reading standard input: %w", scanner.Err()))
		}
	}

	if err := scanner.Err(); err != nil {
		handleError(err)
	}
}

func replaceWithRegex(ctx context.Context, line string, provider providers.SecretProvider) string {
	matches := provider.GetRegex().FindAllStringSubmatch(line, -1)
	for _, match := range matches {
		secretPath := strings.TrimSpace(match[1])
		targetKey := ""
		if strings.Contains(secretPath, "//") {
			parts := strings.Split(secretPath, "//")
			secretPath = parts[0]
			targetKey = parts[1]
		}

		var secretValue string
		var err error

		// Check if the value exists in the cache
		if value, ok := cache.Load(provider.GetPrefix() + secretPath); ok {
			secretValue = value.(string)
			fmt.Fprintf(os.Stderr, "> get [cached] %s (checksum: %s) \n", secretPath, checksum(secretValue))
		} else {
			fmt.Fprintf(os.Stderr, "> get [%s] %s ", provider.GetPrefix(), secretPath)
			for i := 1; i <= retries; i++ {
				secretValue, err = provider.GetSecretValue(ctx, secretPath)
				if err == nil {
					fmt.Fprintf(os.Stderr, "(checksum: %s) \n", checksum(secretValue))
					break
				}
				fmt.Fprintf(os.Stderr, "Error fetching secret %s (attempt %d): %v\n", secretPath, i, err)
			}
			if err != nil {
				handleError(fmt.Errorf("Error fetching secret %s: %w", match[0], err))
				continue
			}

			// Cache the fetched value
			cache.Store(provider.GetPrefix()+secretPath, secretValue)
		}

		if targetKey != "" {
			// Try parsing as JSON first
			var jsonData map[string]interface{}
			if err := json.Unmarshal([]byte(secretValue), &jsonData); err == nil {
				if value, ok := jsonData[targetKey]; ok {
					secretValue = fmt.Sprintf("%v", value)
				} else {
					handleError(fmt.Errorf("Key %s not found in JSON for secret %s", targetKey, match[0]))
					continue
				}
			} else {
				// JSON parsing failed, try YAML
				var yamlData map[string]interface{}
				decoder := yaml.NewDecoder(bytes.NewReader([]byte(secretValue)))
				decoder.KnownFields(true) // Important for v3 to access private fields
				if err := decoder.Decode(&yamlData); err == nil {
					if value, ok := yamlData[targetKey]; ok {
						secretValue = fmt.Sprintf("%v", value)
					} else {
						handleError(fmt.Errorf("Key %s not found in YAML for secret %s", targetKey, match[0]))
						continue
					}
				} else {
					handleError(fmt.Errorf("Failed to parse secret value as JSON or YAML: %w", err))
					continue
				}
			}
		}

		// Replace the template with the secret value
		line = strings.Replace(line, match[0], secretValue, 1)
	}
	return line
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func checksum(data string) string {
	hash := sha256.New()
	hash.Write([]byte(data))
	hashed := hash.Sum(nil)
	truncatedHash := hashed[:8]
	return hex.EncodeToString(truncatedHash)
}

func handleError(err error) {
	fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)

	if !ignoreErrors {
		os.Exit(1)
	}
}
