package executor

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v6/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
)

// defaultChromeVersion is the Chrome TLS fingerprint version used for all outbound connections.
// This is critical for avoiding OpenAI's bot detection which fingerprints standard Go TLS.
const defaultChromeVersion = "chrome133"

// httpClientCache caches HTTP clients by proxy URL to enable connection reuse
var (
	httpClientCache      = make(map[string]*http.Client)
	httpClientCacheMutex sync.RWMutex
)

// newProxyAwareHTTPClient creates an HTTP client with proper proxy configuration priority:
// 1. Use auth.ProxyURL if configured (highest priority)
// 2. Use cfg.ProxyURL if auth proxy is not configured
// 3. Use RoundTripper from context if neither are configured
//
// This function caches HTTP clients by proxy URL to enable TCP/TLS connection reuse.
//
// Parameters:
//   - ctx: The context containing optional RoundTripper
//   - cfg: The application configuration
//   - auth: The authentication information
//   - timeout: The client timeout (0 means no timeout)
//
// Returns:
//   - *http.Client: An HTTP client with configured proxy or transport
func newProxyAwareHTTPClient(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth, timeout time.Duration) *http.Client {
	// Priority 1: Use auth.ProxyURL if configured
	var proxyURL string
	if auth != nil {
		proxyURL = strings.TrimSpace(auth.ProxyURL)
	}

	// Priority 2: Use cfg.ProxyURL if auth proxy is not configured
	if proxyURL == "" && cfg != nil {
		proxyURL = strings.TrimSpace(cfg.ProxyURL)
	}

	// Build cache key from proxy URL (empty string for no proxy)
	cacheKey := proxyURL

	// Check cache first
	httpClientCacheMutex.RLock()
	if cachedClient, ok := httpClientCache[cacheKey]; ok {
		httpClientCacheMutex.RUnlock()
		// Return a wrapper with the requested timeout but shared transport
		if timeout > 0 {
			return &http.Client{
				Transport: cachedClient.Transport,
				Timeout:   timeout,
			}
		}
		return cachedClient
	}
	httpClientCacheMutex.RUnlock()

	// Create new client
	httpClient := &http.Client{}
	if timeout > 0 {
		httpClient.Timeout = timeout
	}

	// If we have a proxy URL configured, set up the transport
	if proxyURL != "" {
		transport := buildProxyTransport(proxyURL)
		if transport != nil {
			httpClient.Transport = transport
			// Cache the client
			httpClientCacheMutex.Lock()
			httpClientCache[cacheKey] = httpClient
			httpClientCacheMutex.Unlock()
			return httpClient
		}
		// If proxy setup failed, log and fall through to context RoundTripper
		log.Debugf("failed to setup proxy from URL: %s, falling back to context transport", proxyURL)
	}

	// No proxy: use utls transport for direct connections
	if proxyURL == "" {
		transport := NewUTLSTransport(defaultChromeVersion, "")
		httpClient.Transport = transport
		httpClientCacheMutex.Lock()
		httpClientCache[cacheKey] = httpClient
		httpClientCacheMutex.Unlock()
		return httpClient
	}

	// Priority 3: Use RoundTripper from context (typically from RoundTripperFor)
	if rt, ok := ctx.Value("cliproxy.roundtripper").(http.RoundTripper); ok && rt != nil {
		httpClient.Transport = rt
	}

	// Cache the client for no-proxy case
	if proxyURL == "" {
		httpClientCacheMutex.Lock()
		httpClientCache[cacheKey] = httpClient
		httpClientCacheMutex.Unlock()
	}

	return httpClient
}

// buildProxyTransport creates an HTTP transport configured for the given proxy URL.
// It supports SOCKS5, HTTP, and HTTPS proxy protocols.
// TLS connections use utls to mimic Chrome's TLS fingerprint (anti-detection).
//
// Parameters:
//   - proxyURL: The proxy URL string (e.g., "socks5://user:pass@host:port", "http://host:port")
//
// Returns:
//   - *http.Transport: A configured transport with utls TLS, or nil if the proxy URL is invalid
func buildProxyTransport(proxyURL string) *http.Transport {
	transport, _, errBuild := proxyutil.BuildHTTPTransport(proxyURL)
	if errBuild != nil {
		log.Errorf("%v", errBuild)
		return nil
	}
	// Apply utls Chrome fingerprint to TLS connections
	if transport != nil {
		applyUTLSToTransport(transport)
	}
	return transport
}

// applyUTLSToTransport replaces the standard TLS dialing with utls Chrome fingerprint.
// Handles: direct connections, SOCKS5 proxy, and HTTP/HTTPS proxy (via CONNECT).
func applyUTLSToTransport(transport *http.Transport) {
	if transport == nil {
		return
	}

	origDial := transport.DialContext
	origProxy := transport.Proxy

	// Override DialTLSContext to apply utls fingerprint on top of any proxy tunnel
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}

		// Step 1: Establish base connection (TCP or proxy tunnel)
		var baseConn net.Conn
		dialer := &net.Dialer{Timeout: 15 * time.Second}

		if origDial != nil {
			// SOCKS5 or custom dialer: use it for the base connection
			baseConn, err = origDial(ctx, network, addr)
		} else if origProxy != nil {
			// HTTP proxy: dial the proxy host directly, then CONNECT
			proxyURL, proxyErr := origProxy(&http.Request{URL: &url.URL{Scheme: "https", Host: addr}})
			if proxyErr == nil && proxyURL != nil {
				proxyHost := proxyURL.Host
				baseConn, err = dialer.DialContext(ctx, "tcp", proxyHost)
				if err == nil {
					// Send CONNECT request
					connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, host)
					_, err = baseConn.Write([]byte(connectReq))
					if err == nil {
						// Read CONNECT response
						buf := make([]byte, 4096)
						n, readErr := baseConn.Read(buf)
						if readErr != nil || !bytes.Contains(buf[:n], []byte("200")) {
							baseConn.Close()
							err = fmt.Errorf("proxy CONNECT failed: %s", string(buf[:n]))
						}
					}
				}
			} else {
				// No proxy for this URL
				baseConn, err = dialer.DialContext(ctx, network, addr)
			}
		} else {
			// Direct TCP dial
			baseConn, err = dialer.DialContext(ctx, network, addr)
		}

		if err != nil {
			return nil, err
		}

		// Step 2: Wrap with utls Chrome fingerprint
		return WrapConnWithUTLS(baseConn, host, defaultChromeVersion)
	}

	log.Debugf("utls: applied Chrome %s TLS fingerprint to transport", defaultChromeVersion)
}
