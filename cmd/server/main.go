package main

import (
	"database/sql"
	"log"
	"net/http"
	"strconv"
	"time"

	_ "github.com/lib/pq"

	"g-auth/internal/config"
	"g-auth/internal/handler"
	"g-auth/internal/middleware"
	"g-auth/internal/repository/postgres"
	"g-auth/internal/service"
	"g-auth/pkg/jwt"
	"g-auth/pkg/logger"
	"g-auth/pkg/mailer"
)

func main() {
	// load configuration
	cfg := config.Load()

	// initialize logger
	appLogger, err := logger.NewLogger(cfg.Env)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer appLogger.Sync()

	// initialize database connection
	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		appLogger.Fatal("Failed to connect to database: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		appLogger.Fatal("Failed to ping database: %v", err)
	}

	// initialize JWT manager
	jwtManager := jwt.NewJWTManager(cfg.JWTSecret, cfg.JWTExpiration, cfg.RefreshTokenExpiration)

	// initialize mailer
	smtpPort, _ := strconv.Atoi(cfg.SMTPPort)
	var emailMailer mailer.Mailer
	if cfg.SMTPHost != "" && cfg.SMTPUsername != "" && cfg.SMTPPassword != "" {
		emailMailer = mailer.NewSMTPMailer(cfg.SMTPHost, smtpPort, cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPFrom)
	} else {
		// Use no-op mailer if SMTP is not configured
		emailMailer = mailer.NewNoOpMailer()
		appLogger.Warn("SMTP not configured, using no-op mailer")
	}

	// initialize repositories
	userRepo := postgres.NewUserRepository(db)

	// initialize services
	authService := service.NewAuthService(userRepo, jwtManager, emailMailer)

	// initialize HTTP handler
	handler := handler.NewAuthHandler(authService)

	// setup router with middleware
	router := handler.SetupRoutes()
	router.Use(middleware.TraceMiddleware)
	router.Use(middleware.LoggingMiddleware(appLogger))

	// start server
	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	appLogger.Info("Server starting", "port", cfg.Port)
	if err := server.ListenAndServe(); err != nil {
		appLogger.Fatal("Server failed to start", "error", err)
	}
}
