# Deployment Guide

## Table of Contents
- [Prerequisites](#prerequisites)
- [Environment Configuration](#environment-configuration)
- [Deployment Options](#deployment-options)
- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Cloud Deployment](#cloud-deployment)
- [Production Checklist](#production-checklist)
- [Monitoring Setup](#monitoring-setup)
- [Backup and Recovery](#backup-and-recovery)

---

## Prerequisites

### Required Software
- Go 1.25.3 or higher
- PostgreSQL 15 or higher
- Docker (for containerized deployment)
- Docker Compose (optional, for local development)
- kubectl (for Kubernetes deployment)

### Required Knowledge
- Basic understanding of Docker
- Familiarity with PostgreSQL
- Understanding of environment variables
- Basic networking concepts

---

## Environment Configuration

### Required Environment Variables

Create a `.env` file (or set system environment variables):

```bash
# Application Environment
ENV=production                    # Options: development, staging, production

# Server Configuration
PORT=8080                         # Port the service listens on

# Database Configuration
DATABASE_URL=postgres://username:password@hostname:5432/dbname?sslmode=require

# JWT Configuration
JWT_SECRET=your-super-secret-key-minimum-32-characters-long
```

### Environment Variable Details

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| ENV | Application environment | development | No |
| PORT | HTTP server port | 8080 | No |
| DATABASE_URL | PostgreSQL connection string | - | Yes |
| JWT_SECRET | Secret key for JWT signing | - | Yes |

### Security Notes

- **JWT_SECRET**: Use a strong, random key (minimum 32 characters)
- **DATABASE_URL**: Use SSL mode (`sslmode=require`) in production
- Never commit `.env` files to version control
- Rotate secrets regularly
- Use secret management tools in production (e.g., AWS Secrets Manager, HashiCorp Vault)

---

## Deployment Options

### 1. Binary Deployment

**Best for**: Simple deployments, VPS hosting

#### Steps:

1. **Build the binary**:
   ```bash
   make build
   ```

2. **Copy binary to server**:
   ```bash
   scp bin/auth-service user@server:/opt/auth-service/
   ```

3. **Set up environment variables on server**:
   ```bash
   sudo nano /etc/systemd/system/auth-service.env
   ```

4. **Create systemd service**:
   ```bash
   sudo nano /etc/systemd/system/auth-service.service
   ```
   
   ```ini
   [Unit]
   Description=G-Auth Authentication Service
   After=network.target postgresql.service

   [Service]
   Type=simple
   User=authuser
   WorkingDirectory=/opt/auth-service
   EnvironmentFile=/etc/systemd/system/auth-service.env
   ExecStart=/opt/auth-service/auth-service
   Restart=on-failure
   RestartSec=10

   [Install]
   WantedBy=multi-user.target
   ```

5. **Start the service**:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable auth-service
   sudo systemctl start auth-service
   ```

6. **Check status**:
   ```bash
   sudo systemctl status auth-service
   ```

---

### 2. Docker Deployment

**Best for**: Containerized environments, easy scaling

#### Dockerfile

Create a `Dockerfile` in the project root:

```dockerfile
# Build stage
FROM golang:1.25.3-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o auth-service cmd/server/main.go

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy binary from builder
COPY --from=builder /app/auth-service .

# Expose port
EXPOSE 8080

# Run the application
CMD ["./auth-service"]
```

#### Build and Run

```bash
# Build the Docker image
docker build -t g-auth:latest .

# Run the container
docker run -d \
  --name g-auth \
  -p 8080:8080 \
  -e ENV=production \
  -e DATABASE_URL="postgres://user:pass@host:5432/db?sslmode=require" \
  -e JWT_SECRET="your-secret-key" \
  --restart unless-stopped \
  g-auth:latest
```

#### Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    container_name: auth-postgres
    environment:
      POSTGRES_DB: authdb
      POSTGRES_USER: authuser
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./migrations:/docker-entrypoint-initdb.d
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U authuser -d authdb"]
      interval: 10s
      timeout: 5s
      retries: 5

  auth-service:
    build: .
    container_name: g-auth
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      ENV: production
      PORT: 8080
      DATABASE_URL: postgres://authuser:${DB_PASSWORD}@postgres:5432/authdb?sslmode=disable
      JWT_SECRET: ${JWT_SECRET}
    ports:
      - "8080:8080"
    restart: unless-stopped

volumes:
  postgres_data:
```

**Run with Docker Compose**:

```bash
# Create .env file with secrets
echo "DB_PASSWORD=your_db_password" > .env
echo "JWT_SECRET=your_jwt_secret" >> .env

# Start services
docker-compose up -d

# View logs
docker-compose logs -f auth-service

# Stop services
docker-compose down
```

---

### 3. Kubernetes Deployment

**Best for**: Production-scale deployments, auto-scaling

#### Prerequisites

- Kubernetes cluster (EKS, GKE, AKS, or self-hosted)
- kubectl configured
- Container registry (Docker Hub, ECR, GCR, etc.)

#### Kubernetes Manifests

**1. Namespace** (`k8s/namespace.yaml`):

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: auth-system
```

**2. ConfigMap** (`k8s/configmap.yaml`):

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: auth-config
  namespace: auth-system
data:
  ENV: "production"
  PORT: "8080"
```

**3. Secret** (`k8s/secret.yaml`):

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: auth-secret
  namespace: auth-system
type: Opaque
stringData:
  DATABASE_URL: "postgres://user:password@postgres:5432/authdb?sslmode=require"
  JWT_SECRET: "your-super-secret-jwt-key"
```

**4. Deployment** (`k8s/deployment.yaml`):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
  namespace: auth-system
spec:
  replicas: 3
  selector:
    matchLabels:
      app: auth-service
  template:
    metadata:
      labels:
        app: auth-service
    spec:
      containers:
      - name: auth-service
        image: your-registry/g-auth:latest
        ports:
        - containerPort: 8080
        envFrom:
        - configMapRef:
            name: auth-config
        - secretRef:
            name: auth-secret
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "128Mi"
            cpu: "200m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
```

**5. Service** (`k8s/service.yaml`):

```yaml
apiVersion: v1
kind: Service
metadata:
  name: auth-service
  namespace: auth-system
spec:
  selector:
    app: auth-service
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8080
  type: LoadBalancer
```

**6. Horizontal Pod Autoscaler** (`k8s/hpa.yaml`):

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: auth-service-hpa
  namespace: auth-system
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: auth-service
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

#### Deploy to Kubernetes

```bash
# Create namespace
kubectl apply -f k8s/namespace.yaml

# Create configmap and secret
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secret.yaml

# Deploy application
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml

# Set up autoscaling
kubectl apply -f k8s/hpa.yaml

# Check deployment status
kubectl get pods -n auth-system
kubectl get svc -n auth-system

# View logs
kubectl logs -f -n auth-system -l app=auth-service
```

---

## Cloud Deployment

### AWS (ECS with Fargate)

#### 1. Push Image to ECR

```bash
# Authenticate Docker to ECR
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <account-id>.dkr.ecr.us-east-1.amazonaws.com

# Build and tag image
docker build -t g-auth .
docker tag g-auth:latest <account-id>.dkr.ecr.us-east-1.amazonaws.com/g-auth:latest

# Push image
docker push <account-id>.dkr.ecr.us-east-1.amazonaws.com/g-auth:latest
```

#### 2. Create RDS PostgreSQL Instance

```bash
aws rds create-db-instance \
  --db-instance-identifier auth-db \
  --db-instance-class db.t3.micro \
  --engine postgres \
  --master-username authuser \
  --master-user-password <password> \
  --allocated-storage 20 \
  --vpc-security-group-ids <sg-id> \
  --db-subnet-group-name <subnet-group> \
  --backup-retention-period 7 \
  --storage-encrypted
```

#### 3. Create ECS Task Definition

```json
{
  "family": "auth-service",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "containerDefinitions": [
    {
      "name": "auth-service",
      "image": "<account-id>.dkr.ecr.us-east-1.amazonaws.com/g-auth:latest",
      "portMappings": [
        {
          "containerPort": 8080,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "ENV",
          "value": "production"
        },
        {
          "name": "PORT",
          "value": "8080"
        }
      ],
      "secrets": [
        {
          "name": "DATABASE_URL",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:<account-id>:secret:auth/database-url"
        },
        {
          "name": "JWT_SECRET",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:<account-id>:secret:auth/jwt-secret"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/auth-service",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

### Google Cloud Platform (Cloud Run)

```bash
# Build and push to GCR
gcloud builds submit --tag gcr.io/<project-id>/g-auth

# Deploy to Cloud Run
gcloud run deploy g-auth \
  --image gcr.io/<project-id>/g-auth \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars ENV=production,PORT=8080 \
  --set-secrets=DATABASE_URL=auth-database-url:latest,JWT_SECRET=auth-jwt-secret:latest \
  --min-instances 1 \
  --max-instances 10 \
  --cpu 1 \
  --memory 512Mi
```

---

## Production Checklist

### Pre-Deployment

- [ ] Set strong JWT_SECRET (minimum 32 characters)
- [ ] Configure DATABASE_URL with SSL enabled
- [ ] Set ENV=production
- [ ] Review and set appropriate resource limits
- [ ] Set up database backups
- [ ] Configure logging to external service
- [ ] Set up monitoring and alerting
- [ ] Perform load testing
- [ ] Document rollback procedure
- [ ] Review security configurations

### Security

- [ ] Use HTTPS (TLS/SSL certificates)
- [ ] Enable database SSL connections
- [ ] Set up firewall rules
- [ ] Implement rate limiting
- [ ] Configure CORS properly
- [ ] Use secrets management service
- [ ] Enable audit logging
- [ ] Scan Docker images for vulnerabilities
- [ ] Keep dependencies updated

### Database

- [ ] Run database migrations
- [ ] Set up connection pooling
- [ ] Configure appropriate timeout settings
- [ ] Enable query logging (temporarily for troubleshooting)
- [ ] Set up read replicas (for scaling)
- [ ] Configure automatic backups
- [ ] Test restore procedures

### Monitoring

- [ ] Set up application logs
- [ ] Configure health check endpoints
- [ ] Set up uptime monitoring
- [ ] Configure error tracking (e.g., Sentry)
- [ ] Set up performance monitoring (APM)
- [ ] Create dashboards
- [ ] Configure alerts for critical metrics
- [ ] Set up log aggregation

---

## Monitoring Setup

### Application Logs

Logs are structured JSON in production mode. Configure log forwarding:

**Using FluentD**:

```yaml
# fluent.conf
<source>
  @type forward
  port 24224
</source>

<match auth.service.**>
  @type elasticsearch
  host elasticsearch.logging.svc.cluster.local
  port 9200
  logstash_format true
  logstash_prefix auth-service
</match>
```

### Health Checks

The service exposes a health endpoint:

```bash
# Kubernetes liveness probe
curl http://localhost:8080/health

# Expected response
{"status":"ok"}
```

### Prometheus Metrics (Future Enhancement)

Add Prometheus metrics export:

```go
// Metrics to track
- http_requests_total
- http_request_duration_seconds
- auth_successful_logins_total
- auth_failed_logins_total
- jwt_tokens_issued_total
- database_connections_active
```

---

## Backup and Recovery

### Database Backups

#### Automated Backups (PostgreSQL)

```bash
# Daily backup script
#!/bin/bash
BACKUP_DIR="/backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/authdb_$DATE.sql.gz"

pg_dump $DATABASE_URL | gzip > $BACKUP_FILE

# Keep only last 30 days
find $BACKUP_DIR -name "authdb_*.sql.gz" -mtime +30 -delete
```

#### Restore from Backup

```bash
# Restore database
gunzip < backup_file.sql.gz | psql $DATABASE_URL
```

### Application State

The service is stateless. All state is in PostgreSQL. No additional backup needed for application state.

---

## Troubleshooting

### Common Issues

**Issue: Service won't start**
```bash
# Check logs
docker logs g-auth
kubectl logs -n auth-system -l app=auth-service

# Common causes:
- Database connection failure
- Invalid JWT_SECRET
- Port already in use
```

**Issue: Database connection errors**
```bash
# Verify database is accessible
psql $DATABASE_URL -c "SELECT 1;"

# Check connection string format
# Format: postgres://user:pass@host:port/db?sslmode=require
```

**Issue: JWT authentication fails**
```bash
# Verify JWT_SECRET is set
echo $JWT_SECRET

# Check token expiration
# Default: 1 minute (very short for testing)
```

---

**Last Updated**: January 10, 2026
