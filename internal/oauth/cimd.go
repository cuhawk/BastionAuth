package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxMetadataBytes = 64 << 10
const metadataTTL = 5 * time.Minute

var errMetadata = errors.New("invalid client metadata")

type metadataDocument struct {
	ID             string   `json:"client_id"`
	Name           string   `json:"client_name"`
	Redirects      []string `json:"redirect_uris"`
	Authentication string   `json:"token_endpoint_auth_method,omitempty"`
}

type metadataEntry struct {
	document     metadataDocument
	etag         string
	cacheControl []string
	expires      time.Time
}

// CIMDResolver resolves public OAuth clients from HTTPS metadata documents.
type CIMDResolver struct {
	client *http.Client
	mu     sync.Mutex
	cache  map[string]metadataEntry
}

func NewCIMDResolver() *CIMDResolver {
	return &CIMDResolver{client: newPublicHTTPSClient(), cache: make(map[string]metadataEntry)}
}

func newPublicHTTPSClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext:            dialMetadata,
			MaxIdleConns:           32,
			IdleConnTimeout:        30 * time.Second,
			MaxResponseHeaderBytes: 64 << 10,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

var blockedMetadataNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("168.63.129.16/32"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

var globalIPv6 = netip.MustParsePrefix("2000::/3")

func publicMetadataIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsPrivate() || (ip.Is6() && !globalIPv6.Contains(ip)) {
		return false
	}
	for _, network := range blockedMetadataNetworks {
		if network.Contains(ip) {
			return false
		}
	}
	return true
}

func dialMetadata(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, errMetadata
	}
	// Validate every DNS answer and dial the checked address without resolving it again.
	for _, ip := range ips {
		if !publicMetadataIP(ip) {
			return nil, errMetadata
		}
	}
	dialer := net.Dialer{}
	for _, ip := range ips {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
	}
	return nil, errMetadata
}

func metadataURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && len(raw) <= 2048 && u.Scheme == "https" && u.Hostname() != "" &&
		u.User == nil && !strings.ContainsAny(u.Hostname(), "*%") && u.Path != "" && !u.ForceQuery && u.RawQuery == "" && !strings.Contains(raw, "#")
}

func metadataRedirect(raw string) bool {
	return ValidRedirectURI(raw, true)
}

// ValidRedirectURI validates OAuth callback syntax and rejects reserved query parameters.
func ValidRedirectURI(raw string, allowLoopback bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || strings.ContainsAny(u.Hostname(), "*%") || strings.ContainsAny(raw, "#\\") {
		return false
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return false
	}
	for _, key := range authorizationFields {
		if query.Has(key) {
			return false
		}
	}
	for _, key := range []string{"code", "error", "error_description", "error_uri", "iss", "request", "request_uri", "resource", "response_mode"} {
		if query.Has(key) {
			return false
		}
	}
	if !allowLoopback && u.Scheme != "https" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	ip, err := netip.ParseAddr(u.Hostname())
	return u.Scheme == "http" && err == nil && ip.IsLoopback()
}

func (r *CIMDResolver) resolve(ctx context.Context, id string) (metadataDocument, error) {
	if !metadataURL(id) {
		return metadataDocument{}, errMetadata
	}
	now := time.Now()
	r.mu.Lock()
	previous := r.cache[id]
	r.mu.Unlock()
	if now.Before(previous.expires) {
		return previous.document, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, id, nil)
	if err != nil {
		return metadataDocument{}, err
	}
	req.Header.Set("Accept", "application/json")
	if previous.etag != "" {
		req.Header.Set("If-None-Match", previous.etag)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return metadataDocument{}, err
	}
	defer resp.Body.Close()
	entry := previous
	switch resp.StatusCode {
	case http.StatusNotModified:
		if previous.etag == "" {
			return metadataDocument{}, errMetadata
		}
	case http.StatusOK:
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataBytes+1))
		if err != nil || len(data) > maxMetadataBytes {
			return metadataDocument{}, errMetadata
		}
		entry = metadataEntry{}
		if err := decodeMetadata(data, &entry.document); err != nil {
			return metadataDocument{}, errMetadata
		}
		doc := entry.document
		if doc.ID != id || len(doc.Redirects) == 0 {
			return metadataDocument{}, errMetadata
		}
		for _, redirect := range doc.Redirects {
			if !metadataRedirect(redirect) {
				return metadataDocument{}, errMetadata
			}
		}
	default:
		return metadataDocument{}, errMetadata
	}
	if etag := resp.Header.Get("ETag"); etag != "" {
		entry.etag = etag
	}
	if control := resp.Header.Values("Cache-Control"); len(control) > 0 {
		entry.cacheControl = control
	}
	ttl, cacheable := metadataFreshness(entry.cacheControl, resp.Header.Get("Age"))
	entry.expires = now.Add(ttl)
	r.mu.Lock()
	defer r.mu.Unlock()
	if !cacheable {
		delete(r.cache, id)
		return entry.document, nil
	}
	if len(r.cache) >= 256 {
		for key, value := range r.cache {
			if !now.Before(value.expires) {
				delete(r.cache, key)
			}
		}
		if len(r.cache) >= 256 {
			for key := range r.cache {
				delete(r.cache, key)
				break
			}
		}
	}
	r.cache[id] = entry
	return entry.document, nil
}

func decodeMetadata(data []byte, doc *metadataDocument) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return errMetadata
	}
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return errMetadata
		}
		seen[key] = true
		var errDecode error
		switch key {
		case "client_id":
			errDecode = decoder.Decode(&doc.ID)
		case "client_name":
			errDecode = decoder.Decode(&doc.Name)
		case "redirect_uris":
			errDecode = decoder.Decode(&doc.Redirects)
		case "token_endpoint_auth_method":
			errDecode = decoder.Decode(&doc.Authentication)
			if doc.Authentication != "none" {
				return errMetadata
			}
		default:
			var ignored json.RawMessage
			errDecode = decoder.Decode(&ignored)
		}
		if errDecode != nil {
			return errMetadata
		}
	}
	if _, err := decoder.Token(); err != nil {
		return errMetadata
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errMetadata
	}
	return nil
}

func metadataFreshness(cacheControl []string, ageHeader string) (time.Duration, bool) {
	ttl := metadataTTL
	for _, field := range strings.Split(strings.Join(cacheControl, ","), ",") {
		key, value, _ := strings.Cut(strings.TrimSpace(field), "=")
		switch strings.ToLower(key) {
		case "no-store":
			return 0, false
		case "no-cache":
			ttl = 0
		case "max-age":
			seconds, err := strconv.ParseUint(strings.Trim(value, "\""), 10, 32)
			if err == nil {
				ttl = min(ttl, time.Duration(seconds)*time.Second)
			}
		}
	}
	if age, err := strconv.ParseUint(ageHeader, 10, 32); err == nil {
		ttl = max(0, ttl-time.Duration(age)*time.Second)
	}
	return ttl, true
}

func (s Server) resolveClient(ctx context.Context, id string) (Client, string, bool) {
	if client, ok := s.Clients[id]; ok {
		return client, id, true
	}
	if s.CIMD == nil {
		return Client{}, "", false
	}
	document, err := s.CIMD.resolve(ctx, id)
	if err != nil {
		return Client{}, "", false
	}
	name := id
	if document.Name != "" {
		name = document.Name + " (" + id + ")"
	}
	return Client{Redirects: document.Redirects, Scopes: s.CIMDScopes}, name, true
}
