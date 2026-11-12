package dynamictransport

import (
	"crypto/x509"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewRoundTripperWithoutProvidersReturnsHTTPTransport(t *testing.T) {
	roundTripper, err := NewRoundTripper(t.Context())
	require.NoError(t, err)
	require.IsType(t, &http.Transport{}, roundTripper)
}

// TestTrustSourcesHandshake verifies each static trust source with a real TLS
// handshake against an httptest server, including that WithCertPool pins trust:
// sources outside the pool are rejected.
func TestTrustSourcesHandshake(t *testing.T) {
	poolCA := newTestCA(t, "pool-ca")
	dataCA := newTestCA(t, "data-ca")
	fileCA := newTestCA(t, "file-ca")
	otherCA := newTestCA(t, "other-ca")

	pool := x509.NewCertPool()
	pool.AddCert(poolCA.certificate)
	emptyPool := x509.NewCertPool()

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, fileCA.pem, 0600))

	testCases := []struct {
		name        string
		opts        []Option
		trustedCA   *testCA
		untrustedCA *testCA
	}{
		{
			name:        "default system pool rejects the test CA",
			opts:        nil,
			trustedCA:   nil,
			untrustedCA: poolCA,
		},
		{
			name:        "cert pool trusts its CA",
			opts:        []Option{WithCertPool(pool)},
			trustedCA:   poolCA,
			untrustedCA: otherCA,
		},
		{
			name:        "empty cert pool trusts nothing",
			opts:        []Option{WithCertPool(emptyPool)},
			trustedCA:   nil,
			untrustedCA: poolCA,
		},
		{
			name:        "CA data trusts its CA",
			opts:        []Option{WithCAData("data", dataCA.pem)},
			trustedCA:   dataCA,
			untrustedCA: otherCA,
		},
		{
			name:        "CA file trusts its CA",
			opts:        []Option{WithCAFile("file", caFile)},
			trustedCA:   fileCA,
			untrustedCA: otherCA,
		},
		{
			name: "cert pool pins trust when combined with CA data",
			opts: []Option{
				WithCertPool(emptyPool),
				WithCAData("data", dataCA.pem),
			},
			trustedCA:   dataCA,
			untrustedCA: otherCA,
		},
		{
			name: "pool, data and file combined trust all their CAs",
			opts: []Option{
				WithCertPool(pool),
				WithCAData("data", dataCA.pem),
				WithCAFile("file", caFile),
			},
			trustedCA:   fileCA,
			untrustedCA: otherCA,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			roundTripper, err := NewRoundTripper(t.Context(), tc.opts...)
			require.NoError(t, err)
			t.Cleanup(roundTripper.(interface{ CloseIdleConnections() }).CloseIdleConnections)

			if tc.trustedCA != nil {
				server := startTLSServer(t, tc.trustedCA.serverCertificate, nil)
				assertTrusted(t, roundTripper, server.URL)
			}
			if tc.untrustedCA != nil {
				server := startTLSServer(t, tc.untrustedCA.serverCertificate, nil)
				assertUntrusted(t, roundTripper, server.URL)
			}
		})
	}
}
