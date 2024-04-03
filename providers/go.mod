module providers

go 1.20

replace github.com/mikhae1/secfetch/providers => ./

require (
	github.com/aws/aws-sdk-go v1.51.12
	github.com/mikhae1/secfetch/providers v0.0.0-00010101000000-000000000000
)

require github.com/jmespath/go-jmespath v0.4.0 // indirect
