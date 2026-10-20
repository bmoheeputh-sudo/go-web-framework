package authconfig

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDiscoveryRetryIsBoundedAndIdempotentOnly(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		var calls atomic.Int32
		transport := discoveryRetryTransport{base: testRoundTrip(func(*http.Request) (*http.Response, error) {
			n := calls.Add(1)
			code := status
			if n == 3 {
				code = http.StatusOK
			}
			return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader("{}")), Header: make(http.Header)}, nil
		}), delay: func(int) time.Duration { return 0 }}
		request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://provider.example.test/jwks", nil)
		response, err := transport.RoundTrip(request)
		if err != nil || response.StatusCode != http.StatusOK || calls.Load() != 3 {
			t.Fatal("transient GET was not retried safely", status, calls.Load(), err)
		}
		response.Body.Close()
	}
	var calls atomic.Int32
	transport := discoveryRetryTransport{base: testRoundTrip(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(strings.NewReader("{}")), Header: make(http.Header)}, nil
	}), delay: func(int) time.Duration { return 0 }}
	post, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://provider.example.test/token", strings.NewReader("code=x"))
	if response, err := transport.RoundTrip(post); err != nil || response.StatusCode != http.StatusServiceUnavailable || calls.Load() != 1 {
		t.Fatal("non-idempotent request retried", err)
	}
	calls.Store(0)
	get, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://provider.example.test/jwks", nil)
	if response, err := transport.RoundTrip(get); err != nil || response.StatusCode != http.StatusServiceUnavailable || calls.Load() != 3 {
		t.Fatal("retry bound not enforced", err, calls.Load())
	}
}
