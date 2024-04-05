# Go binary name
BINARY=secfetch

# Go build flags
BUILD_FLAGS=-ldflags="-s -w"

# Go test flags
TEST_FLAGS=-v

# Default target: build the binary
all: test vet build

# Build the binary
build:
	go build $(BUILD_FLAGS) -o $(BINARY) .

# Run tests
test:
	cd ./providers && go test $(TEST_FLAGS) ./...
	go test $(TEST_FLAGS) ./...

vet:
	go vet ./...

# Clean up build artifacts
clean:
	rm -f $(BINARY)
