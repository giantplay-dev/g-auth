.PHONY: run build clean test coverage mod-tidy migrate-up migrate-down migrate-001-up migrate-001-down migrate-002-up migrate-002-down migrate-003-up migrate-003-down migrate-004-up migrate-004-down migrate-005-up migrate-005-down migrate-006-up migrate-006-down docker-up docker-down docker-migrate docker-build docker-run help dev

# Load environment variables
include .env
export

# Default target
help:
	@echo "Available commands:"
	@echo "  run                 - Run the application"
	@echo "  build               - Build the application"
	@echo "  clean               - Clean build artifacts"
	@echo "  test                - Run all tests"
	@echo "  coverage            - Run tests with coverage report"
	@echo "  mod-tidy            - Tidy and verify go modules"
	@echo "  migrate-up          - Run all up migrations"
	@echo "  migrate-down        - Run all down migrations"
	@echo "  migrate-001-up      - Run migration 001 up"
	@echo "  migrate-001-down    - Run migration 001 down"
	@echo "  migrate-002-up      - Run migration 002 up"
	@echo "  migrate-002-down    - Run migration 002 down"
	@echo "  migrate-003-up      - Run migration 003 up"
	@echo "  migrate-003-down    - Run migration 003 down"
	@echo "  migrate-004-up      - Run migration 004 up"
	@echo "  migrate-004-down    - Run migration 004 down"
	@echo "  migrate-005-up      - Run migration 005 up"
	@echo "  migrate-005-down    - Run migration 005 down"
	@echo "  migrate-006-up      - Run migration 006 up"
	@echo "  migrate-006-down    - Run migration 006 down"
	@echo "  docker-up           - Start PostgreSQL in Docker"
	@echo "  docker-down         - Stop and remove PostgreSQL Docker container"
	@echo "  docker-migrate      - Run migrations in Docker container"
	@echo "  docker-build        - Build Docker image"
	@echo "  docker-run          - Run service in Docker"
	@echo "  dev                 - Set up development environment"

run:
	go run cmd/server/main.go

build:
	go build -o bin/auth-service cmd/server/main.go

# Clean build artifacts
clean:
	rm -rf bin/
	go clean

test:
	go test -v ./...

coverage:
	go test -coverprofile=coverage/coverage.out ./...
	go tool cover -html=coverage/coverage.out -o coverage/coverage.html
	@echo "Coverage report generated: coverage/coverage.html"

mod-tidy:
	go mod tidy
	go mod verify

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

migrate-004-up:
	psql $(DATABASE_URL) -f migrations/004_add_email_verification_fields.up.sql

migrate-004-down:
	psql $(DATABASE_URL) -f migrations/004_add_email_verification_fields.down.sql

migrate-005-up:
	psql $(DATABASE_URL) -f migrations/005_add_account_lockout_fields.up.sql

migrate-005-down:
	psql $(DATABASE_URL) -f migrations/005_add_account_lockout_fields.down.sql

migrate-006-up:
	psql $(DATABASE_URL) -f migrations/006_add_mfa_fields.up.sql

migrate-006-down:
	psql $(DATABASE_URL) -f migrations/006_add_mfa_fields.down.sql

migrate-up: migrate-001-up migrate-002-up migrate-003-up migrate-004-up migrate-005-up migrate-006-up
	@echo "All migrations applied successfully"

migrate-down: migrate-006-down migrate-005-down migrate-004-down migrate-003-down migrate-002-down migrate-001-down
	@echo "All migrations rolled back successfully"

# Docker commands
docker-up:
	docker stop auth-postgres || true
	docker rm auth-postgres || true
	docker run --name auth-postgres \
		-e POSTGRES_USER=postgres \
		-e POSTGRES_PASSWORD=postgres \
		-e POSTGRES_DB=g-auth \
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
	docker exec -i auth-postgres psql -U postgres -d g-auth -f /dev/stdin < migrations/001_create_users_table.up.sql
	docker exec -i auth-postgres psql -U postgres -d g-auth -f /dev/stdin < migrations/002_add_password_reset_fields.up.sql
	docker exec -i auth-postgres psql -U postgres -d g-auth -f /dev/stdin < migrations/003_add_refresh_token_fields.up.sql
	docker exec -i auth-postgres psql -U postgres -d g-auth -f /dev/stdin < migrations/004_add_email_verification_fields.up.sql
	docker exec -i auth-postgres psql -U postgres -d g-auth -f /dev/stdin < migrations/005_add_account_lockout_fields.up.sql
	docker exec -i auth-postgres psql -U postgres -d g-auth -f /dev/stdin < migrations/006_add_mfa_fields.up.sql
	@echo "Migrations completed successfully"

docker-build:
	docker build -t auth-service:latest -f deploy/Dockerfile .

docker-run:
	docker run --network host --env-file .env -e DATABASE_URL=postgres://postgres:postgres@localhost:5432/g-auth?sslmode=disable auth-service:latest

dev: docker-up docker-migrate
	@echo "Development environment is ready!"
	@echo "Run 'make run' to start the service"
	@echo "Run 'make test' to run tests"