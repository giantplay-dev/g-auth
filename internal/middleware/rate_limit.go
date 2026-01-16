package middleware

import (
	"net/http"
	"strings"
	"sync"

	"golang.org/x/time/rate"

	"g-auth/internal/config"
)

var (
	// Map of rate limiters per IP address
	limiters = make(map[string]*rate.Limiter)
	mu       sync.RWMutex
)

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxy/load balancer scenarios)
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	// Remove port if present
	if strings.Contains(ip, ":") {
		ip, _, _ = strings.Cut(ip, ":")
	}
	return ip
}

// getLimiter returns a rate limiter for the given IP address
func getLimiter(ip string, cfg *config.Config) *rate.Limiter {
	mu.Lock()
	defer mu.Unlock()

	limiter, exists := limiters[ip]
	if !exists {
		// Create a new rate limiter for this IP
		limiter = rate.NewLimiter(rate.Limit(cfg.RateLimit), cfg.RateLimitBurst)
		limiters[ip] = limiter
	}

	return limiter
}

// RateLimitMiddleware limits the number of requests per second per IP address
func RateLimitMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := getClientIP(r)
			limiter := getLimiter(ip, cfg)

			if !limiter.Allow() {
				http.Error(w, "Too many requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
