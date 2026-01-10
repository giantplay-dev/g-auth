package middleware

import (
	"net/http"
	"time"

	"g-auth/pkg/logger"
)

type responseWriter struct {
	http.ResponseWriter
	status int
	size   int
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(b)
	rw.size += size
	return size, err
}

// loggingMiddleware logs all HTTP requests with trace ID
func LoggingMiddleware(log *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// get trace ID from context
			traceID := r.Context().Value(TraceIDKey).(string)

			// create logger with trace ID
			reqLogger := log.With("trace_id", traceID)

			// wrap response writer to capture status code
			rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}

			// log request
			reqLogger.Info("incoming request",
				"method", r.Method,
				"path", r.URL.Path,
				"remote_addr", r.RemoteAddr,
				"user_agent", r.UserAgent(),
			)

			// process request
			next.ServeHTTP(rw, r)

			// log response
			duration := time.Since(start)
			reqLogger.Info("request completed",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rw.status,
				"duration_ms", duration.Milliseconds(),
				"size_bytes", rw.size,
			)
		})
	}
}
