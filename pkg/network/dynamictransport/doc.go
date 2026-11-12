// Package dynamictransport builds outbound HTTP round trippers whose CA trust
// can follow dynamically reloaded CA content providers.
//
// # Static and dynamic transports
//
// New returns a static *http.Transport when no CA content provider is
// supplied, and a wrapper when one or more are. The concrete type of the
// returned http.RoundTripper is not part of the API, but the static path
// returns a plain *http.Transport and starts no goroutines. The wrapper
// forwards CloseIdleConnections, so http.Client.CloseIdleConnections works in
// either case.
//
// # Trust sources
//
// The trust pool is assembled from the base pool (WithCertPool, defaulting to
// the system pool), static PEM data (WithCAData, WithCAFile), and the current
// bundles of the CA content providers (WithCAContentProvider). All sources are
// combined. WithCertPool replaces the system pool entirely, so it can be used
// to pin trust to exactly the supplied certificates.
//
// # Rebuild semantics
//
// When a provider reports a change, the wrapper snapshots every provider's
// current bundle, builds a new transport from that snapshot, and swaps it in
// for new connections. Rebuilds are coalesced (a burst of notifications
// triggers one rebuild), serialized, and retried with backoff if building the
// new transport fails. If the new content cannot be parsed, the previous
// transport stays in use until a rebuild succeeds; a replacement is therefore
// not instantaneous under failure. Connections already established are not
// re-verified; idle connections held by the replaced transport are closed.
//
// A periodic resync bounds how long a missed provider notification can go
// unnoticed.
//
// # Lifecycle
//
// New takes a context. When the context is done, the wrapper stops following
// its providers (notifications are ignored) and keeps serving the last
// transport it built. Callers that want a fresh trust state should build a new
// round tripper.
//
// Callers own the lifecycle of supplied CA content providers. Construct all
// round trippers before starting the providers' Run: the dynamiccertificates
// providers do not synchronize AddListener, so adding a listener to a running
// provider is a data race.
package dynamictransport
