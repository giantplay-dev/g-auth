.PHONY: run build test migrate-up migrate-down migrate-all-up migrate-all-down migrate-001-up migrate-001-down migrate-002-up migrate-002-down docker-up docker-down docker-migrate docker-build docker-run clean help dev

# Load environment variables
include .env
export

# Default target
help:
	@echo "Available commands:"
	@echo "  run                 - Run the application"
	@echo "  build               - Build the application"
	@echo "  test                - Run all tests"
	@echo "  migrate-up          - Run all up migrations"
	@echo "  migrate-down        - Run all down migrations"
	@echo "  migrate-001-up      - Run migration 001 up"
	@echo "  migrate-001-down    - Run migration 001 down"
	@echo "  migrate-002-up      - Run migration 002 up"
	@echo "  migrate-002-down    - Run migration 002 down"
	@echo "  migrate-003-up      - Run migration 003 up"
	@echo "  migrate-003-down    - Run migration 003 down"
	@echo "  docker-up           - Start PostgreSQL in Docker"
	@echo "  docker-down         - Stop and remove PostgreSQL Docker container"
	@echo "  docker-migrate      - Run migrations in Docker container"
	@echo "  docker-build        - Build Docker image"
	@echo "  docker-run          - Run service in Docker"
	@echo "  clean               - Clean build artifacts"
	@echo "  dev                 - Set up development environment"

run:
	go run cmd/server/main.go

build:
	go build -o bin/auth-service cmd/server/main.go

test:
	go test -v ./...

# Migration commands using psql
migrate-001-up:
	psql $(DATABASE_URL) -f migrations/001_create_users_table.up.sql

migrate-001-down:
	psql $(DATABASE_URL) -f migrations/001_create_users_table.down.sql

migrate-002-up:
	psql $(DATABASE_URL) -f migrations/002_add_password_reset_fields.up.sql

migrate-002-down:
	psql $(DATABASE_URL) -f migrations/002_add_password_reset_fields.down.sql

migrate-003-up:
	psql $(DATABASE_URL) -f migrations/003_add_refresh_token_fields.up.sql

migrate-003-down:
	psql $(DATABASE_URL) -f migrations/003_add_refresh_token_fields.down.sql

migrate-all-up: migrate-001-up migrate-002-up migrate-003-up
	@echo "All migrations applied successfully"

migrate-all-down: migrate-002-down migrate-001-down
	@echo "All migrations rolled back successfully"

# Legacy aliases for backward compatibility
migrate-up: migrate-all-up
migrate-down: migrate-all-down

# Docker commands
docker-up:
	docker run --name auth-postgres \
		-e POSTGRES_PASSWORD=postgres \
		-e POSTGRES_DB=authdb \
		-p 5432:5432 \
		-d postgres:15
	@echo "Waiting for PostgreSQL to start..."
	@sleep 5
	@echo "PostgreSQL is ready!"

docker-down:
	docker stop auth-postgres || true
	docker rm auth-postgres || true

docker-migrate: docker-up
	@echo "Running migrations in Docker container..."
	docker exec -i auth-postgres psql -U postgres -d authdb -f /dev/stdin < migrations/001_create_users_table.up.sql
	docker exec -i auth-postgres psql -U postgres -d authdb -f /dev/stdin < migrations/002_add_password_reset_fields.up.sql
	@echo "Migrations completed successfully"

# Build and run service in Docker
docker-build:
	docker build -t auth-service:latest .

docker-run:
	docker run -p 8080:8080 --env-file .env auth-service:latest

# Clean build artifacts
clean:
	rm -rf bin/
	go clean

# Development workflow
dev: docker-up docker-migrate
	@echo "Development environment is ready!"
	@echo "Run 'make run' to start the service"
	@echo "Run 'make test' to run tests"