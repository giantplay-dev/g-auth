package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"g-auth/pkg/logger"
)

func TestLoggingMiddleware_LogsRequest(t *testing.T) {
	log, err := logger.NewLogger("development")
	assert.NoError(t, err)

	middleware := LoggingMiddleware(log)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("response body"))
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	// Add trace ID to context (required by logging middleware)
	ctx := context.WithValue(req.Context(), TraceIDKey, "test-trace-id")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestLoggingMiddleware_DifferentStatusCodes(t *testing.T) {
	log, err := logger.NewLogger("development")
	assert.NoError(t, err)

	tests := []struct {
		name       string
		statusCode int
	}{
		{"OK", http.StatusOK},
		{"NotFound", http.StatusNotFound},
		{"InternalServerError", http.StatusInternalServerError},
		{"BadRequest", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware := LoggingMiddleware(log)

			handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))

			req := httptest.NewRequest("GET", "/test", nil)
			ctx := context.WithValue(req.Context(), TraceIDKey, "test-trace-id")
			req = req.WithContext(ctx)

			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			assert.Equal(t, tt.statusCode, w.Code)
		})
	}
}

func TestLoggingMiddleware_CapturesResponseSize(t *testing.T) {
	log, err := logger.NewLogger("development")
	assert.NoError(t, err)

	middleware := LoggingMiddleware(log)

	responseBody := "test response body"
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(responseBody))
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	ctx := context.WithValue(req.Context(), TraceIDKey, "test-trace-id")
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, responseBody, w.Body.String())
}

func TestResponseWriter_WriteHeader(t *testing.T) {
	rw := &responseWriter{
		ResponseWriter: httptest.NewRecorder(),
		status:         http.StatusOK,
	}

	rw.WriteHeader(http.StatusNotFound)

	assert.Equal(t, http.StatusNotFound, rw.status)
}

func TestResponseWriter_Write(t *testing.T) {
	recorder := httptest.NewRecorder()
	rw := &responseWriter{
		ResponseWriter: recorder,
		status:         http.StatusOK,
	}

	data := []byte("test data")
	n, err := rw.Write(data)

	assert.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, len(data), rw.size)
}

func TestResponseWriter_MultipleWrites(t *testing.T) {
	recorder := httptest.NewRecorder()
	rw := &responseWriter{
		ResponseWriter: recorder,
		status:         http.StatusOK,
	}

	data1 := []byte("first ")
	data2 := []byte("second")

	n1, err1 := rw.Write(data1)
	n2, err2 := rw.Write(data2)

	assert.NoError(t, err1)
	assert.NoError(t, err2)
	assert.Equal(t, len(data1), n1)
	assert.Equal(t, len(data2), n2)
	assert.Equal(t, len(data1)+len(data2), rw.size)
}

func TestLoggingMiddleware_DifferentHTTPMethods(t *testing.T) {
	log, err := logger.NewLogger("development")
	assert.NoError(t, err)

	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			middleware := LoggingMiddleware(log)

			handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(method, "/test", nil)
			ctx := context.WithValue(req.Context(), TraceIDKey, "test-trace-id")
			req = req.WithContext(ctx)

			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
		})
	}
}
