package api

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/kmpoltorak/ai-network-incident-investigator/internal/observability"
)

var (
	safeRequestID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	// W3C traceparent: version-traceid-parentid-flags
	traceparent = regexp.MustCompile(`^[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$`)
)

// withRequestIDs accepts a well-formed X-Request-ID and W3C traceparent from
// the caller or generates new IDs, and echoes the request ID back.
func withRequestIDs(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-ID")
		if !safeRequestID.MatchString(reqID) {
			reqID = randomHex(16)
		}
		traceID := randomHex(16)
		if m := traceparent.FindStringSubmatch(r.Header.Get("traceparent")); m != nil {
			traceID = m[1]
		}
		w.Header().Set("X-Request-ID", reqID)
		next.ServeHTTP(w, r.WithContext(observability.WithRequestIDs(r.Context(), reqID, traceID)))
	})
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// observe records metrics and an access log line. It must wrap the mux
// directly: the mux sets r.Pattern on this request, which keeps the route
// label bounded to registered patterns instead of raw paths.
func observe(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		route := r.Pattern
		if route == "" {
			route = "unmatched"
		}
		elapsed := time.Since(start)
		observability.HTTPRequestsTotal.WithLabelValues(r.Method, route, strconv.Itoa(rec.status)).Inc()
		observability.HTTPRequestDuration.WithLabelValues(r.Method, route).Observe(elapsed.Seconds())
		if route != "GET /metrics" && route != "GET /health" {
			log.InfoContext(r.Context(), "http request", "method", r.Method, "route", route,
				"status", rec.status, "duration_ms", elapsed.Milliseconds())
		}
	})
}

func recoverPanics(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if err, ok := v.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(v)
				}
				log.ErrorContext(r.Context(), "panic in handler", "panic", v)
				writeError(w, r, http.StatusInternalServerError, "internal", "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
