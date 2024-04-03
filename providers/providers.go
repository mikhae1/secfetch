package providers

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/ssm"
)

// SecretProvider defines the interface for fetching secrets.
type SecretProvider interface {
	GetSecretValue(ctx context.Context, path string) (string, error)
	GetPrefix() string
	GetRegex() *regexp.Regexp
}

// SSMProvider implements the SecretProvider interface for AWS SSM Parameter Store.
type SSMProvider struct {
	client *ssm.SSM
	prefix string
	regex  *regexp.Regexp
}

func NewSSMProvider(client *ssm.SSM, prefix string) *SSMProvider {
	return &SSMProvider{
		client: client,
		prefix: prefix,
		regex:  regexp.MustCompile(prefix + `([a-zA-Z0-9_.-/]+)`),
	}
}

// GetSecretValue retrieves the secret value from AWS SSM Parameter Store.
func (p *SSMProvider) GetSecretValue(ctx context.Context, path string) (string, error) {
	if path != "" && path[0] != '/' {
		path = "/" + path
	}
	input := &ssm.GetParameterInput{
		Name:           aws.String(path),
		WithDecryption: aws.Bool(true),
	}
	res, err := p.client.GetParameterWithContext(ctx, input)
	if err != nil {
		return "", fmt.Errorf("get parameter: %w", err)
	}
	secret := *res.Parameter.Value
	return secret, nil
}

// GetPrefix returns the prefix used for SSM secrets.
func (p *SSMProvider) GetPrefix() string {
	return p.prefix
}

// GetRegex returns the regex used to match SSM secret placeholders.
func (p *SSMProvider) GetRegex() *regexp.Regexp {
	return p.regex
}

// SecretsManagerProvider implements the SecretProvider interface for AWS Secrets Manager.
type SecretsManagerProvider struct {
	client *secretsmanager.SecretsManager
	prefix string
	regex  *regexp.Regexp
}

func NewSecretsManagerProvider(client *secretsmanager.SecretsManager, prefix string) *SecretsManagerProvider {
	return &SecretsManagerProvider{
		client: client,
		prefix: prefix,
		regex:  regexp.MustCompile(prefix + `([a-zA-Z0-9-/_+=.@:]+)`),
	}
}

// GetSecretValue retrieves the secret value from AWS Secrets Manager.
func (p *SecretsManagerProvider) GetSecretValue(ctx context.Context, secretID string) (string, error) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretID),
	}
	res, err := p.client.GetSecretValueWithContext(ctx, input)
	if err != nil {
		return "", fmt.Errorf("get secret value: %w", err)
	}
	if res.SecretString != nil {
		return *res.SecretString, nil
	}
	return "", fmt.Errorf("secret value is nil")
}

// GetPrefix returns the prefix used for Secrets Manager secrets.
func (p *SecretsManagerProvider) GetPrefix() string {
	return p.prefix
}

// GetRegex returns the regex used to match Secrets Manager secret placeholders.
func (p *SecretsManagerProvider) GetRegex() *regexp.Regexp {
	return p.regex
}

// EnvProvider implements the SecretProvider interface for environment variables.
type EnvProvider struct {
	prefix string
	regex  *regexp.Regexp
}

func NewEnvProvider(prefix string) *EnvProvider {
	return &EnvProvider{
		prefix: prefix,
		regex:  regexp.MustCompile(prefix + `([a-zA-Z0-9_]+)`), // Match alphanumeric and underscores
	}
}

// GetSecretValue retrieves the secret value from environment variables.
func (p *EnvProvider) GetSecretValue(ctx context.Context, key string) (string, error) {
	secretValue := os.Getenv(key)
	if secretValue == "" {
		return "", fmt.Errorf("environment variable %s not found", key)
	}
	return secretValue, nil
}

// GetPrefix returns the prefix used for environment variable secrets.
func (p *EnvProvider) GetPrefix() string {
	return p.prefix
}

// GetRegex returns the regex used to match environment variable secret placeholders.
func (p *EnvProvider) GetRegex() *regexp.Regexp {
	return p.regex
}

// Base64Provider implements the SecretProvider interface for Base64 encoded strings.
type Base64Provider struct {
	prefix string
	regex  *regexp.Regexp
}

func NewBase64Provider(prefix string) *Base64Provider {
	return &Base64Provider{
		prefix: prefix,
		regex:  regexp.MustCompile(prefix + `([a-zA-Z0-9+/=]+)`), // Match Base64 characters
	}
}

// GetSecretValue decodes the Base64 encoded string.
func (p *Base64Provider) GetSecretValue(ctx context.Context, encoded string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode base64: %w", err)
	}
	return string(decoded), nil
}

// GetPrefix returns the prefix used for Base64 secrets.
func (p *Base64Provider) GetPrefix() string {
	return p.prefix
}

// GetRegex returns the regex used to match Base64 secret placeholders.
func (p *Base64Provider) GetRegex() *regexp.Regexp {
	return p.regex
}
