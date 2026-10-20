package authconfig

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"
)

var errTestNetwork = errors.New("oidc_test_network_rejected")

// Include special-purpose ranges that IsGlobalUnicast alone accepts. Restrict
// IPv6 to globally allocated unicast and exclude transition/translation ranges.
var blockedTestRanges = func() []netip.Prefix {
	var result []netip.Prefix
	for _, prefix := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"} {
		result = append(result, netip.MustParsePrefix(prefix))
	}
	return result
}()

func publicTestIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, prefix := range blockedTestRanges {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}
func testHTTPS(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.Opaque != "" || (u.Port() != "" && u.Port() != "443") {
		return nil, errTestNetwork
	}
	return u, nil
}

type testNetwork struct {
	lookup func(context.Context, string, string) ([]netip.Addr, error)
	dial   func(context.Context, string, string) (net.Conn, error)
}

func (n testNetwork) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	ips, err := n.lookup(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, errTestNetwork
	}
	for _, ip := range ips {
		if !publicTestIP(ip) {
			return nil, errTestNetwork
		}
	}
	return ips, nil
}
func (n testNetwork) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "443" {
		return nil, errTestNetwork
	}
	ips, err := n.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	// Dial the checked numeric address, never resolve the hostname a second time.
	return n.dial(ctx, network, net.JoinHostPort(ips[0].Unmap().String(), port))
}

type limitedTestBody struct {
	io.ReadCloser
	remaining int64
}

func (b *limitedTestBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		return 0, errTestNetwork
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.ReadCloser.Read(p)
	b.remaining -= int64(n)
	return n, err
}

type testTransport struct {
	base   http.RoundTripper
	origin string
}

// Forward cleanup to the owned transport; no shared default transport is closed.
func (t testTransport) CloseIdleConnections() {
	if c, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}
func (t testTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	u, err := testHTTPS(r.URL.String())
	if err != nil || u.Scheme+"://"+u.Host != t.origin {
		return nil, errTestNetwork
	}
	response, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, errTestNetwork
	}
	response.Body = &limitedTestBody{response.Body, 1 << 20}
	return response, nil
}
func newTestClient(ctx context.Context, issuer string) (*http.Client, error) {
	u, err := testHTTPS(issuer)
	if err != nil {
		return nil, err
	}
	n := testNetwork{net.DefaultResolver.LookupNetIP, (&net.Dialer{Timeout: 3 * time.Second}).DialContext}
	if _, err = n.resolve(ctx, u.Hostname()); err != nil {
		return nil, err
	}
	transport := &http.Transport{Proxy: nil, DialContext: n.dialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 64 << 10, DisableKeepAlives: true}
	return &http.Client{Transport: testTransport{transport, u.Scheme + "://" + u.Host}, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errTestNetwork }}, nil
}
