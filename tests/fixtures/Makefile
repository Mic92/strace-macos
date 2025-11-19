# Makefile for test fixtures

CC = cc
CFLAGS = -Wall -Wextra -std=c99
BUILD_DIR = build

# Default target
all: $(BUILD_DIR)/test_executable

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Build test executable
$(BUILD_DIR)/test_executable: test_executable.c $(wildcard *.h) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $<

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)

# Rebuild everything
rebuild: clean all

.PHONY: all clean rebuild
