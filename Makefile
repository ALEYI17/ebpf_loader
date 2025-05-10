# Makefile for building and pushing Docker images

# Image name with optional tag
IMG ?= ebpf_loader:latest

# Docker or Podman
CONTAINER_TOOL ?= docker

.PHONY: all help docker-build docker-push 

# Default target
all: help

## Show this help message
help:
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

## Build the Docker image
docker-build: 
	$(CONTAINER_TOOL) build -t $(IMG) .

## Push the Docker image
docker-push: 
	$(CONTAINER_TOOL) push $(IMG)



