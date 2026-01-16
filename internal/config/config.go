package config

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Env                    string
	Port                   string
	DatabaseURL            string
	JWTSecret              string
	JWTExpiration          time.Duration
	RefreshTokenExpiration time.Duration
	SMTPHost               string
	SMTPPort               string
	SMTPUsername           string
	SMTPPassword           string
	SMTPFrom               string
	RateLimit              int // requests per second
	RateLimitBurst         int // burst capacity
}

func Load() *Config {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	return &Config{
		Env:                    getEnv("APP_ENV", "development"),
		Port:                   getEnv("APP_PORT", "8080"),
		DatabaseURL:            getEnv("DATABASE_URL", "postgres://user:pass@localhost:5432/dbname"),
		JWTSecret:              getEnv("JWT_SECRET", "supersecretkey"),
		JWTExpiration:          15 * time.Minute,   // Access token: 15 minutes
		RefreshTokenExpiration: 7 * 24 * time.Hour, // Refresh token: 7 days
		SMTPHost:               getEnv("SMTP_HOST", "smtp.gmail.com"),
		SMTPPort:               getEnv("SMTP_PORT", "587"),
		SMTPUsername:           getEnv("SMTP_USERNAME", ""),
		SMTPPassword:           getEnv("SMTP_PASSWORD", ""),
		SMTPFrom:               getEnv("SMTP_FROM", ""),
		RateLimit:              getEnvAsInt("RATE_LIMIT", 10),       // 10 requests per second
		RateLimitBurst:         getEnvAsInt("RATE_LIMIT_BURST", 20), // burst up to 20
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}
