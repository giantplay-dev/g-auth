.PHONY: run build test migrate-up migrate-down docker-up docker-down

# Load environment variables
include .env
export

run:
	go run cmd/server/main.go

build:
	go build -o bin/auth-service cmd/server/main.go

test:
	go test -v ./...

# Option 1: Using psql (requires PostgreSQL client)
migrate-up:
	psql $(DATABASE_URL) -f migrations/001_create_users_table.up.sql

migrate-down:
	psql $(DATABASE_URL) -f migrations/001_create_users_table.down.sql

# Option 2: Using Docker (no psql required)
docker-up:
	docker run --name auth-postgres \
		-e POSTGRES_PASSWORD=postgres \
		-e POSTGRES_DB=authdb \
		-p 5432:5432 \
		-d postgres:15
	@echo "Waiting for PostgreSQL to start..."
	@sleep 3
	docker exec -i auth-postgres psql -U postgres -d authdb < migrations/001_create_users_table.sql

docker-down:
	docker stop auth-postgres
	docker rm auth-postgres

docker-migrate:
	docker exec -i auth-postgres psql -U postgres -d authdb < migrations/001_create_users_table.sql

# Build and run service in Docker
docker-build:
	docker build -t auth-service:latest .

docker-run:
	docker run -p 8080:8080 --env-file .env auth-service:latest