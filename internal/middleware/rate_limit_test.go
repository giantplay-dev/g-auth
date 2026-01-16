package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"g-auth/internal/config"
)

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		expected   string
	}{
		{
			name:       "X-Forwarded-For header",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.1"},
			remoteAddr: "127.0.0.1:12345",
			expected:   "203.0.113.1",
		},
		{
			name:       "X-Forwarded-For with multiple IPs",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.1, 198.51.100.1"},
			remoteAddr: "127.0.0.1:12345",
			expected:   "203.0.113.1",
		},
		{
			name:       "X-Real-IP header",
			headers:    map[string]string{"X-Real-IP": "203.0.113.2"},
			remoteAddr: "127.0.0.1:12345",
			expected:   "203.0.113.2",
		},
		{
			name:       "RemoteAddr fallback",
			headers:    map[string]string{},
			remoteAddr: "203.0.113.3:8080",
			expected:   "203.0.113.3",
		},
		{
			name:       "RemoteAddr without port",
			headers:    map[string]string{},
			remoteAddr: "203.0.113.4",
			expected:   "203.0.113.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			ip := getClientIP(req)
			if ip != tt.expected {
				t.Errorf("getClientIP() = %v, expected %v", ip, tt.expected)
			}
		})
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	// Create a config with low rate limits for testing
	cfg := &config.Config{
		RateLimit:      2, // 2 requests per second
		RateLimitBurst: 2, // burst of 2
	}

	// Create middleware
	middleware := RateLimitMiddleware(cfg)

	// Create a simple handler that just returns 200
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Wrap handler with middleware
	wrappedHandler := middleware(handler)

	t.Run("Allow requests within limit", func(t *testing.T) {
		// First request should be allowed
		req1 := httptest.NewRequest("GET", "/test", nil)
		w1 := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w1, req1)
		if w1.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w1.Code)
		}

		// Second request should be allowed (within burst)
		req2 := httptest.NewRequest("GET", "/test", nil)
		w2 := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w2, req2)
		if w2.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w2.Code)
		}
	})

	t.Run("Block requests over limit", func(t *testing.T) {
		// Third request should be blocked (over burst limit)
		req3 := httptest.NewRequest("GET", "/test", nil)
		w3 := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w3, req3)
		if w3.Code != http.StatusTooManyRequests {
			t.Errorf("Expected status 429, got %d", w3.Code)
		}
	})

	t.Run("Allow after rate limit reset", func(t *testing.T) {
		// Wait for rate limiter to refill
		time.Sleep(1 * time.Second)

		// This request should be allowed again
		req4 := httptest.NewRequest("GET", "/test", nil)
		w4 := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w4, req4)
		if w4.Code != http.StatusOK {
			t.Errorf("Expected status 200 after rate limit reset, got %d", w4.Code)
		}
	})

	t.Run("Different IPs have separate limits", func(t *testing.T) {
		// Create requests with different IPs
		req1 := httptest.NewRequest("GET", "/test", nil)
		req1.RemoteAddr = "192.168.1.1:12345"

		req2 := httptest.NewRequest("GET", "/test", nil)
		req2.RemoteAddr = "192.168.1.2:12345"

		// Both should be allowed since they have different IPs
		w1 := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w1, req1)
		if w1.Code != http.StatusOK {
			t.Errorf("Expected status 200 for first IP, got %d", w1.Code)
		}

		w2 := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w2, req2)
		if w2.Code != http.StatusOK {
			t.Errorf("Expected status 200 for second IP, got %d", w2.Code)
		}
	})
}
