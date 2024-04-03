# secfetch: Fetch and Replace Secrets in Your Input

**secfetch** is a Go script that reads input from stdin, scans for occurrences of specified prefixes followed by secret identifiers, retrieves the corresponding secret values from the appropriate service, and replaces the placeholders in the input with the actual secret values.

## Supported Services

- **AWS Systems Manager Parameter Store (SSM):** `ssm://path/to/secret`
- **AWS Secrets Manager:** `secrets://secret-name`
- **Environment Variables:** `env://VARIABLE_NAME`
- **Base64 encoded strings:** `base64://encoded-string` (not recommended for sensitive data)

## Install:

Download the secfetch script.
Make it executable: `chmod +x secfetch`

## Set environment variables (optional):

```hcl
SEC_SSM_PREFIX: Custom prefix for SSM secrets (default: ssm://)
SEC_SECRETS_PREFIX: Custom prefix for Secrets Manager secrets (default: secrets://)
SEC_ENV_PREFIX: Custom prefix for environment variables (default: env://)
SEC_BASE64_PREFIX: Custom prefix for Base64 encoded strings (default: base64://)
SEC_IGNORE_ERR: Set to any value to ignore errors and continue processing (default: exit on error)
SEC_RETRIES: Number of retries for fetching secrets (default: 3)
SEC_TIMEOUT: Timeout in seconds for fetching secrets (default: 30)
```

## Usage Example

Pipe your input to secfetch:

    cat input.txt | ./secfetch

The script will replace secret placeholders with their actual values in the output.

## Notes

- The script uses regular expressions to match secret placeholders.
- Ensure your custom prefixes don't conflict with other patterns in your input.
- For AWS services, ensure you have the necessary credentials and permissions to access the secrets.
- Base64 encoding is not a secure way to store secrets. Use it only for non-sensitive data.
- The script caches fetched secret values to improve performance.
- Error messages are printed to stderr.
