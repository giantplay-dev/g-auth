package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTraceMiddleware_GeneratesNewTraceID(t *testing.T) {
	var traceIDFromContext interface{}

	handler := TraceMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		traceIDFromContext = r.Context().Value(TraceIDKey)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotNil(t, traceIDFromContext)
	assert.NotEmpty(t, traceIDFromContext.(string))

	// Check trace ID is in response header
	responseTraceID := w.Header().Get("X-Trace-ID")
	assert.NotEmpty(t, responseTraceID)
	assert.Equal(t, traceIDFromContext.(string), responseTraceID)
}

func TestTraceMiddleware_UsesExistingTraceID(t *testing.T) {
	existingTraceID := "existing-trace-id-12345"
	var traceIDFromContext interface{}

	handler := TraceMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		traceIDFromContext = r.Context().Value(TraceIDKey)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Trace-ID", existingTraceID)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, existingTraceID, traceIDFromContext.(string))

	// Check trace ID is propagated to response header
	responseTraceID := w.Header().Get("X-Trace-ID")
	assert.Equal(t, existingTraceID, responseTraceID)
}

func TestTraceMiddleware_TraceIDKeyConstant(t *testing.T) {
	assert.Equal(t, "trace_id", TraceIDKey)
}

func TestTraceMiddleware_PassesRequestToNextHandler(t *testing.T) {
	handlerCalled := false

	handler := TraceMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.True(t, handlerCalled)
}

func TestTraceMiddleware_EmptyTraceIDHeaderGeneratesNew(t *testing.T) {
	var traceIDFromContext interface{}

	handler := TraceMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		traceIDFromContext = r.Context().Value(TraceIDKey)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Trace-ID", "") // Empty trace ID
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Should generate new trace ID since header was empty
	assert.NotEmpty(t, traceIDFromContext.(string))
}

func TestTraceMiddleware_DifferentRequestsGetDifferentTraceIDs(t *testing.T) {
	var traceID1, traceID2 string

	handler := TraceMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request
	req1 := httptest.NewRequest("GET", "/test", nil)
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)
	traceID1 = w1.Header().Get("X-Trace-ID")

	// Second request
	req2 := httptest.NewRequest("GET", "/test", nil)
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	traceID2 = w2.Header().Get("X-Trace-ID")

	assert.NotEmpty(t, traceID1)
	assert.NotEmpty(t, traceID2)
	assert.NotEqual(t, traceID1, traceID2)
}
