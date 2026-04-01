// Package executor provides TLS fingerprint emulation using utls.
// This replaces the default Go TLS handshake with Chrome-mimicking TLS fingerprints
// to avoid detection and ban by OpenAI's anti-bot systems.
package executor

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
	log "github.com/sirupsen/logrus"
)

// chromePresetMap maps simplified chrome version names to utls ClientHelloIDs.
var chromePresetMap = map[string]utls.ClientHelloID{
	"chrome131": utls.HelloChrome_131,
	"chrome133": utls.HelloChrome_133,
	"chrome120": utls.HelloChrome_120,
}

// defaultChromeHelloID is the fallback fingerprint when no version is configured.
var defaultChromeHelloID = utls.HelloChrome_133

// resolveChromeHelloID returns a utls ClientHelloID for the given version string.
// Falls back to Chrome 133 if the version is not recognized.
func resolveChromeHelloID(version string) utls.ClientHelloID {
	if id, ok := chromePresetMap[version]; ok {
		return id
	}
	return defaultChromeHelloID
}

// utlsConn wraps a utls.UConn to implement the net.Conn interface
// so it can be used with the standard http.Transport.
type utlsConn struct {
	*utls.UConn
}

// utlsDialFunc creates a dial function that performs a utls handshake
// mimicking the specified Chrome version's TLS fingerprint.
func utlsDialFunc(helloID utls.ClientHelloID, serverName string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Extract hostname for SNI if not provided
		host := serverName
		if host == "" {
			host, _, _ = net.SplitHostPort(addr)
		}

		// Standard TCP dial with timeout
		dialer := &net.Dialer{Timeout: 15 * time.Second}
		rawConn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, fmt.Errorf("utls tcp dial failed: %w", err)
		}

		// Create utls connection with Chrome fingerprint
		uConn := utls.UClient(rawConn, &utls.Config{
			ServerName: host,
		}, helloID)

		// Perform TLS handshake with timeout
		if deadline, ok := ctx.Deadline(); ok {
			_ = uConn.SetDeadline(deadline)
		} else {
			_ = uConn.SetDeadline(time.Now().Add(15 * time.Second))
		}

		if err := uConn.Handshake(); err != nil {
			_ = rawConn.Close()
			return nil, fmt.Errorf("utls handshake failed: %w", err)
		}
		_ = uConn.SetDeadline(time.Time{})

		log.Debugf("utls: connected to %s with %s fingerprint", addr, helloID.Str())
		return &utlsConn{UConn: uConn}, nil
	}
}

// NewUTLSTransport creates an http.Transport that uses utls for TLS connections.
// The transport mimics Chrome's TLS fingerprint to avoid detection.
//
// Parameters:
//   - chromeVersion: e.g. "chrome131", "chrome133", "chrome120"
//   - serverName: SNI hostname (extracted from addr if empty)
//
// Returns an http.Transport with utls-based TLS dialing and Chrome-like HTTP/2 settings.
func NewUTLSTransport(chromeVersion string, serverName string) *http.Transport {
	helloID := resolveChromeHelloID(chromeVersion)

	transport := &http.Transport{
		DialTLSContext: utlsDialFunc(helloID, serverName),
		// Match Chrome's HTTP/2 settings
		ForceAttemptHTTP2: true,
		// Connection pool settings
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	return transport
}

// RequestJitter adds a random delay between requests to mimic human timing.
// Call this before making requests in rapid succession.
func RequestJitter() time.Duration {
	var n uint32
	_ = binary.Read(crand.Reader, binary.BigEndian, &n)
	delay := time.Duration(200+n%1300) * time.Millisecond
	time.Sleep(delay)
	return delay
}

// NewUTLSTLSConfig creates a *tls.Config that can be used with custom dialers
// while maintaining Chrome-like TLS behavior via utls.
// This is mainly for websocket dialers that need explicit TLS configuration.
func NewUTLSTLSConfig(serverName string) *tls.Config {
	return &tls.Config{
		ServerName: serverName,
		// These are set for compatibility; actual fingerprint comes from utls
		InsecureSkipVerify: false,
	}
}

// WrapConnWithUTLS performs a utls handshake on an existing net.Conn.
// Useful for wrapping proxy connections (e.g., after HTTP CONNECT).
func WrapConnWithUTLS(conn net.Conn, serverName string, chromeVersion string) (net.Conn, error) {
	helloID := resolveChromeHelloID(chromeVersion)

	uConn := utls.UClient(conn, &utls.Config{
		ServerName: serverName,
	}, helloID)

	if err := uConn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("utls handshake failed: %w", err)
	}

	return &utlsConn{UConn: uConn}, nil
}
