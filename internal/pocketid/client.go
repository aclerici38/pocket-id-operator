// Package pocketid connects the operator to Pocket-ID through the generated v3 client.
package pocketid

import (
	"cmp"
	"context"
	"crypto/tls"
	"fmt"
	"iter"
	"net/http"
	"strings"
	"time"

	"github.com/aclerici38/pocket-id-go-client/v3/client"
	"github.com/oapi-codegen/nullable"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const logoutTimeout = 5 * time.Second

// Client is the generated Pocket-ID client, plus the HTTP client a user session reuses.
type Client struct {
	*client.Client
	httpClient *http.Client
}

// ClientOption customizes the HTTP client a Client sends requests through.
type ClientOption func(*http.Client)

// WithTLSConfig makes the client use cfg for HTTPS connections. A nil cfg is a no-op,
// leaving Go's default verification against the system trust store in place.
func WithTLSConfig(cfg *tls.Config) ClientOption {
	return func(hc *http.Client) {
		if cfg == nil {
			return
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = cfg
		hc.Transport = transport
	}
}

// WithHTTPClient sends every request, including a user session's, through a copy of base.
func WithHTTPClient(base *http.Client) ClientOption {
	return func(hc *http.Client) { *hc = *base }
}

// NewClient creates a client for the Pocket-ID instance at baseURL, authenticated with apiKey.
func NewClient(baseURL, apiKey string, opts ...ClientOption) (*Client, error) {
	hc := &http.Client{}
	for _, opt := range opts {
		opt(hc)
	}
	hc.Transport = metricsTransport{next: cmp.Or[http.RoundTripper](hc.Transport, http.DefaultTransport)}

	c, err := client.NewClient(baseURL, client.WithHTTPClient(hc), client.WithAPIKey(apiKey))
	if err != nil {
		return nil, fmt.Errorf("create pocket-id client: %w", err)
	}
	return &Client{Client: c, httpClient: hc}, nil
}

// WithUserSession runs fn in a session for the user, the only credential that can manage keys
// the user owns, and ends the session once fn returns.
func (c *Client) WithUserSession(ctx context.Context, userID string, tokenTTL time.Duration, fn func(*client.Client) error) error {
	token, err := client.Decode[client.TokenCreatedDto](c.CreateOneTimeAccessTokenForUserAdmin(ctx, userID,
		client.TokenCreateDto{TTL: new(int64(tokenTTL.Seconds()))}))
	if err != nil {
		return fmt.Errorf("create one-time access token: %w", err)
	}

	session, err := client.NewSession(ctx, c.Server, token.Token, c.httpClient)
	if err != nil {
		return fmt.Errorf("exchange one-time access token: %w", err)
	}
	// A created key's token is only returned once, so a failed logout must not fail the call, and
	// a cancelled reconcile must not leave the session behind.
	defer func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), logoutTimeout)
		defer cancel()
		if err := client.Check(session.Logout(ctx)); err != nil {
			logf.FromContext(ctx).Error(err, "Failed to end user session", "userID", userID)
		}
	}()

	return fn(session)
}

const (
	// MaxOIDCClientSecrets is Pocket-ID's cap on secrets per client, expired ones included.
	MaxOIDCClientSecrets = 20

	// OIDCClientSecretPrefixLength is how much of a secret Pocket-ID keeps in clear text.
	OIDCClientSecretPrefixLength = 4

	// ClientTypeCIMD marks a client synthesized from an OAuth Client ID Metadata Document.
	ClientTypeCIMD = "cimd"
)

// SecretPrefix returns the prefix Pocket-ID would record for value, or "" if it is too short.
func SecretPrefix(value string) string {
	if len(value) <= OIDCClientSecretPrefixLength {
		return ""
	}
	return value[:OIDCClientSecretPrefixLength]
}

// LooksLikeCIMDID reports whether a client ID is a metadata document URL. Pocket-ID refuses
// to register a standard client under an https URL, so an "https://" prefix can only come
// from a metadata document. It needs no API round trip, which is what makes it usable before a
// client has been resolved. It matches the CRD's CEL admission rules and upstream's
// fosite.LooksLikeCIMDURL, which both require the https scheme.
func LooksLikeCIMDID(id string) bool {
	return strings.HasPrefix(id, "https://")
}

// DefaultAPIKeyExpiry returns a default expiry time of 1 year from now for API keys.
func DefaultAPIKeyExpiry() time.Time {
	return time.Now().AddDate(1, 0, 0)
}

// NullIfEmpty sends an empty string as null, for fields Pocket-ID rejects or indexes uniquely
// when empty.
func NullIfEmpty(s string) nullable.Nullable[string] {
	if s == "" {
		return nullable.NewNullNullable[string]()
	}
	return nullable.NewNullableWithValue(s)
}

// SearchUsers yields matches across all result pages.
func (c *Client) SearchUsers(ctx context.Context, search string) iter.Seq2[client.UserDto, error] {
	return client.All[client.UserDto](func(page int) (*http.Response, error) {
		return c.ListUsers(ctx, &client.ListUsersParams{Search: &search, PaginationPage: &page})
	})
}

// SearchUserGroups yields matches across all result pages.
func (c *Client) SearchUserGroups(ctx context.Context, search string) iter.Seq2[client.UserGroupMinimalDto, error] {
	return client.All[client.UserGroupMinimalDto](func(page int) (*http.Response, error) {
		return c.ListUserGroups(ctx, &client.ListUserGroupsParams{Search: &search, PaginationPage: &page})
	})
}
