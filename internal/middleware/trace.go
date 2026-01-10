package middleware

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

const TraceIDKey = "trace_id"

// traceMiddleware adds a unique trace ID to each request
func TraceMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// check if trace ID exists in header (for distributed tracing)
		traceID := r.Header.Get("X-Trace-ID")
		if traceID == "" {
			// generate new trace ID
			traceID = uuid.New().String()
		}

		// add trace ID to response header
		w.Header().Set("X-Trace-ID", traceID)

		// add trace ID to context
		ctx := context.WithValue(r.Context(), TraceIDKey, traceID)

		// continue with the request
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
