# Secfetch

**secfetch** reads input from stdin, scans for occurrences of specified prefixes followed by secret identifiers in the following placeholder syntax:
`{prefix}//{secret-path}//{target-key}`, retrieves the corresponding secret values from the appropriate service, and replaces the placeholders in the input with the actual secret values.

## Supported Services

- **AWS Systems Manager Parameter Store (SSM):** `ssm://path/to/secret`
- **AWS Secrets Manager:** `secrets://secret-name`
- **Environment Variables:** `env://VARIABLE_NAME`
- **Base64 encoded strings:** `base64://encoded-string` (not recommended for sensitive data)

## Usage Example

    echo 'I am a "base64://c2VjcmV0"!' | ./secfetch

The script will replace secret placeholders with their actual values in the output:

    I am a "secret"!

### Target Keys

You can specify a target key within a secret to extract a specific value from structured secrets (e.g., JSON or YAML). This is useful when your secret contains multiple key-value pairs, and you only need a particular value.

Suppose you have a secret stored in AWS Secrets Manager named `my-api-keys` with the following JSON content:

```json
{
  "stripe_key": "sk_test_...",
  "twilio_key": "AC..."
}
```

Or in yaml format:

```yaml
stripe_key: "sk_test_...",
twilio_key: "AC..."
```

To extract the `stripe_key` value, you would use the following placeholder in your input:

    stripe_key: "secrets://my-api-keys//stripe_key"

#### Base64 Encoding

You can now optionally encode secret values to Base64 by including `//base64` in the secret path. This can be useful for handling binary data or ensuring compatibility with systems that expect Base64-encoded secrets, like Helm charts.

##### Example:

    echo 'My secret key is "secrets://my-api-keys//stripe_key//base64"' | ./secfetch

This will fetch the stripe_key from the `my-api-keys` secret in AWS Secrets Manager, encode it to Base64, and then replace the placeholder with the encoded value.

## Features

- **Custom prefixes**: you can use your own prefixes, reusing existing configuration
- **Caching**: speed up and reduce the number of API calls
- **Retries**: minimize automation errors

## Install:

- Download the `secfetch` binary from [latest Releases](https://github.com/mikhae1/secfetch/releases)
- Unzip and make it executable: `chmod +x secfetch`

## Supported environment variables:

- `SEC_SSM_PREFIX`: Custom prefix for SSM secrets (default: ssm://)
- `SEC_SECRETS_PREFIX`: Custom prefix for Secrets Manager secrets (default: secrets://)
- `SEC_ENV_PREFIX`: Custom prefix for environment variables (default: env://)
- `SEC_BASE64_PREFIX`: Custom prefix for Base64 encoded strings (default: base64://)
- `SEC_IGNORE_ERR`: Set to any value to ignore errors and continue processing (default: exit on error)
- `SEC_RETRIES`: Number of retries for fetching secrets (default: 3)
- `SEC_TIMEOUT`: Timeout in seconds for fetching secrets (default: 30)
