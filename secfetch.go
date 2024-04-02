///usr/bin/true; exec /usr/bin/env go run "$0" "$@"

//
// The script reads input from stdin, scans for occurrences of the specified prefixes followed by the secret identifier,
// retrieves the corresponding secret value from the appropriate service, and replaces the placeholders in the input with the actual secret values.
// It supports:
// - "ssm://" AWS Parameters Store
// - "secrets://" AWS Secrets Manager
//

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/ssm"
)

var (
	ssmPrefix     = getEnv("SEC_SSM_PREFIX", "ssm://")
	secretsPrefix = getEnv("SEC_SECRETS_PREFIX", "secrets://")
	ignoreErrors  = os.Getenv("SEC_IGNORE_ERR") != ""
	retries, _    = strconv.Atoi(getEnv("RETRIES", "3"))

	cache sync.Map
)

func main() {
	awsSess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	ssmClient := ssm.New(awsSess)
	secretsClient := secretsmanager.New(awsSess)

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		replacedLine := replaceSecrets(line, ssmClient, secretsClient)
		fmt.Println(replacedLine)

		if !ignoreErrors && scanner.Err() != nil {
			handleError(fmt.Errorf("Error reading standard input: %v", scanner.Err()))
		}
	}

	if err := scanner.Err(); err != nil {
		handleError(err)
	}
}

func replaceSecrets(line string, ssmClient *ssm.SSM, secretsClient *secretsmanager.SecretsManager) string {
	ssmPrefixRegex := regexp.MustCompile(ssmPrefix + `([a-zA-Z0-9_.-/]+)`)
	secretsPrefixRegex := regexp.MustCompile(secretsPrefix + `([a-zA-Z0-9-/_+=.@:]+)`)

	line = replaceWithRegex(line, ssmPrefixRegex, ssmPrefix, ssmClient)
	line = replaceWithRegex(line, secretsPrefixRegex, ssmPrefix, secretsClient)

	return line
}

func replaceWithRegex(line string, regex *regexp.Regexp, prefix string, client interface{}) string {
	matches := regex.FindAllStringSubmatch(line, -1)

	for _, match := range matches {
		secretPath := strings.TrimSpace(match[1])
		jsonKey := ""

		if strings.Contains(secretPath, "//") {
			parts := strings.Split(secretPath, "//")
			secretPath = parts[0]
			jsonKey = parts[1]
		}

		var secretValue string
		var err error

		// Check if the value exists in the cache
		if value, ok := cache.Load(prefix + secretPath); ok {
			secretValue = value.(string)
			fmt.Fprintf(os.Stderr, "> get cached: %s (checksum: %s) \n", secretPath, checksum(secretValue))
		} else {
			for i := 1; i <= retries; i++ {
				switch client := client.(type) {
				case *ssm.SSM:
					secretValue, err = getSSMSecretValue(secretPath, client)
				case *secretsmanager.SecretsManager:
					secretValue, err = getSecretsManagerSecretValue(secretPath, client)
				}

				if err == nil {
					break
				}

				fmt.Fprintf(os.Stderr, "Error fetching secret %s (attempt %d): %v\n", secretPath, i, err)
			}

			if err != nil {
				handleError(fmt.Errorf("Error fetching secret %s: %v", match[0], err))
				continue
			}

			// Cache the fetched value
			cache.Store(prefix+secretPath, secretValue)
		}

		if jsonKey != "" {
			var jsonData map[string]interface{}
			if err := json.Unmarshal([]byte(secretValue), &jsonData); err != nil {
				handleError(err)
				continue
			}

			if value, ok := jsonData[jsonKey]; ok {
				secretValue = fmt.Sprintf("%v", value)
			} else {
				handleError(fmt.Errorf("Key %s not found in JSON for secret %s", jsonKey, match[0]))
				continue
			}
		}

		// Replace the template with the secret value
		line = strings.Replace(line, match[0], secretValue, 1)
	}

	return line
}

func getSSMSecretValue(path string, client *ssm.SSM) (string, error) {
	if path != "" && path[0] != '/' {
		path = "/" + path
	}

	input := &ssm.GetParameterInput{
		Name:           aws.String(path),
		WithDecryption: aws.Bool(true),
	}

	fmt.Fprintf(os.Stderr, "> get ssm: %s ", path)
	res, err := client.GetParameter(input)
	if err != nil {
		return "", fmt.Errorf("get parameter: %v", err)
	}

	secret := *res.Parameter.Value
	fmt.Fprintf(os.Stderr, "(checksum: %s)\n", checksum(secret))

	return secret, nil
}

func getSecretsManagerSecretValue(secretID string, client *secretsmanager.SecretsManager) (string, error) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretID),
	}

	fmt.Fprintf(os.Stderr, "> get secrets: %s ", secretID)
	res, err := client.GetSecretValue(input)
	if err != nil {
		return "", fmt.Errorf("get secret value: %v", err)
	}

	if res.SecretString != nil {
		fmt.Fprintf(os.Stderr, "(checksum: %s)\n", checksum(*res.SecretString))
		return *res.SecretString, nil
	}

	return "", fmt.Errorf("secret value is nil")
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
