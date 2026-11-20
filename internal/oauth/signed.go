package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cuhawk/BastionAuth/internal/joseutil"
	"github.com/cuhawk/BastionAuth/internal/store"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
const maxSignedJWT = 5 * time.Minute
const maxSignedBytes = 64 << 10

var signedAlgorithms = []jose.SignatureAlgorithm{jose.PS256, jose.ES256, jose.EdDSA}

var errSignedJWT = errors.New("invalid signed JWT")

func (c Client) ValidateSigning() error {
	if c.PrivateKeyJWT && c.SecretDigest != "" {
		return errors.New("private_key_jwt and client_secret_basic are mutually exclusive")
	}
	if (c.RequireJAR || c.PrivateKeyJWT || len(c.RequestURIs) != 0) && len(c.JWTKeys) == 0 {
		return errors.New("signed requests and client assertions require registered public keys")
	}
	kids := make(map[string]bool)
	for _, key := range c.JWTKeys {
		if !key.Valid() || !key.IsPublic() || (key.Use != "" && key.Use != "sig") ||
			!slices.ContainsFunc(signedAlgorithms, func(alg jose.SignatureAlgorithm) bool {
				return (key.Algorithm == "" || key.Algorithm == string(alg)) && joseutil.Matches(string(alg), key.Key)
			}) {
			return errors.New("invalid JWT signing key")
		}
		if key.KeyID != "" {
			if kids[key.KeyID] {
				return errors.New("duplicate JWT signing key ID")
			}
			kids[key.KeyID] = true
		}
	}
	for _, uri := range c.RequestURIs {
		if !metadataURL(uri) {
			return errors.New("request URI must be a registered HTTPS URL with a path and without query or fragment")
		}
	}
	return nil
}

// signedClaims accepts only compact JWS and verifies it against registered public keys.
func signedClaims(raw string, keys []jose.JSONWebKey, assertion bool) (map[string]json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > maxSignedBytes || strings.ContainsAny(raw, " \r\n\t") {
		return nil, errSignedJWT
	}
	jws, err := jose.ParseSignedCompact(raw, signedAlgorithms)
	if err != nil {
		return nil, errSignedJWT
	}
	header := jws.Signatures[0].Header
	if header.JSONWebKey != nil {
		return nil, errSignedJWT
	}
	for _, prohibited := range []jose.HeaderKey{"jku", "x5u", "x5c", "crit", "b64"} {
		if _, present := header.ExtraHeaders[prohibited]; present {
			return nil, errSignedJWT
		}
	}
	if typ, present := header.ExtraHeaders[jose.HeaderType]; present {
		if typ != "JWT" && (assertion || typ != "oauth-authz-req+jwt") {
			return nil, errSignedJWT
		}
	}
	for _, key := range keys {
		if !key.Valid() || !key.IsPublic() || !joseutil.Matches(header.Algorithm, key.Key) ||
			(key.Algorithm != "" && key.Algorithm != header.Algorithm) || (key.Use != "" && key.Use != "sig") {
			continue
		}
		if assertion || (header.KeyID != "" && header.KeyID != key.KeyID) {
			thumbprint, err := joseutil.Thumbprint(key)
			if err != nil || !equal(header.KeyID, thumbprint) {
				continue
			}
		}
		if payload, err := jws.Verify(key.Key); err == nil {
			return uniqueClaims(payload)
		}
	}
	return nil, errSignedJWT
}

func uniqueClaims(payload []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(payload))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return nil, errSignedJWT
	}
	claims := make(map[string]json.RawMessage)
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		if err != nil || !ok || claims[name] != nil {
			return nil, errSignedJWT
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, errSignedJWT
		}
		claims[name] = value
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return nil, errSignedJWT
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errSignedJWT
	}
	return claims, nil
}

func stringClaim(raw json.RawMessage) (string, bool) {
	var value *string
	if json.Unmarshal(raw, &value) != nil || value == nil {
		return "", false
	}
	return *value, true
}

func signedTime(raw json.RawMessage) (time.Time, bool) {
	seconds, err := strconv.ParseFloat(string(raw), 64)
	if err != nil || seconds < -(1<<53) || seconds > 1<<53 {
		return time.Time{}, false
	}
	whole, fractional := math.Modf(seconds)
	return time.Unix(int64(whole), int64(fractional*float64(time.Second))), true
}

type signedIdentity struct {
	id, jti string
	expires time.Time
}

func validateSignedClaims(claims map[string]json.RawMessage, id string, audiences []string, now time.Time, assertion bool) (signedIdentity, error) {
	iss, _ := stringClaim(claims["iss"])
	jti, _ := stringClaim(claims["jti"])
	var aud jwt.Audience
	exp, validExpiry := signedTime(claims["exp"])
	if id == "" || iss != id || jti == "" || len(jti) > 256 ||
		json.Unmarshal(claims["aud"], &aud) != nil || len(aud) != 1 || aud[0] == "" || !slices.Contains(audiences, aud[0]) ||
		!validExpiry || !exp.After(now) || exp.After(now.Add(maxSignedJWT)) {
		return signedIdentity{}, errSignedJWT
	}
	if raw, present := claims["nbf"]; present || !assertion {
		nbf, validNBF := signedTime(raw)
		if !validNBF || nbf.After(now) || !nbf.Before(exp) {
			return signedIdentity{}, errSignedJWT
		}
	}
	if assertion {
		sub, _ := stringClaim(claims["sub"])
		if sub != id {
			return signedIdentity{}, errSignedJWT
		}
	}
	return signedIdentity{id: id, jti: jti, expires: exp}, nil
}

func (s Server) claimSigned(ctx context.Context, purpose string, identity signedIdentity) error {
	now := time.Now()
	if !identity.expires.After(now) {
		return errSignedJWT
	}
	// Keep a client's replay namespace stable across key rotation and endpoint audiences.
	// The prefix separates JWT claims from the base64url DPoP thumbprints in this store.
	key := "jwt:" + purpose + ":" + store.Digest(identity.id)
	claimed, err := s.Store.ClaimProof(ctx, s.Tenant, key, identity.jti, now, identity.expires)
	if err != nil {
		return err
	}
	if !claimed {
		return errSignedJWT
	}
	return nil
}

func (s Server) assertionClient(r *http.Request, p url.Values) (string, Client, error) {
	if p.Get("client_assertion_type") != assertionType || p.Has("client_secret") || len(r.Header.Values("Authorization")) != 0 {
		return "", Client{}, errSignedJWT
	}
	raw := p.Get("client_assertion")
	if len(raw) == 0 || len(raw) > maxSignedBytes {
		return "", Client{}, errSignedJWT
	}
	id := p.Get("client_id")
	if !p.Has("client_id") {
		// Only use unverified data to select a registered client's verification keys.
		parsed, err := jwt.ParseSigned(raw, signedAlgorithms)
		var hint jwt.Claims
		if err != nil || parsed.UnsafeClaimsWithoutVerification(&hint) != nil {
			return "", Client{}, errSignedJWT
		}
		id = hint.Issuer
	}
	client, registered := s.Clients[id]
	if !registered || !client.PrivateKeyJWT || client.SecretDigest != "" {
		return "", Client{}, errSignedJWT
	}
	claims, err := signedClaims(raw, client.JWTKeys, true)
	if err != nil {
		return "", Client{}, err
	}
	identity, err := validateSignedClaims(claims, id, []string{s.Exchange.Issuer.Name, s.Origin + r.URL.Path}, time.Now(), true)
	if err != nil {
		return "", Client{}, err
	}
	if err := s.claimSigned(r.Context(), "client-assertion", identity); err != nil {
		return "", Client{}, err
	}
	return id, client, nil
}

func (s Server) requestObject(raw, id string, client Client) (url.Values, signedIdentity, error) {
	claims, err := signedClaims(raw, client.JWTKeys, false)
	if err != nil {
		return nil, signedIdentity{}, err
	}
	identity, err := validateSignedClaims(claims, id, []string{s.Exchange.Issuer.Name}, time.Now(), false)
	if err != nil {
		return nil, signedIdentity{}, err
	}
	if inner, _ := stringClaim(claims["client_id"]); inner != id || claims["request"] != nil || claims["request_uri"] != nil {
		return nil, signedIdentity{}, errSignedJWT
	}
	p := url.Values{}
	for _, field := range authorizationFields {
		raw, present := claims[field]
		if !present {
			continue
		}
		if field == "authorization_details" {
			p.Set(field, string(raw))
			continue
		}
		value, ok := stringClaim(raw)
		if !ok {
			return nil, signedIdentity{}, errSignedJWT
		}
		p.Set(field, value)
	}
	return p, identity, nil
}

func fetchRequestObject(ctx context.Context, client *http.Client, uri string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/oauth-authz-req+jwt, application/jwt")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("request URI returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSignedBytes+1))
	if err != nil || len(body) > maxSignedBytes {
		return "", errSignedJWT
	}
	return string(body), nil
}

func (s Server) frontChannelJAR(r *http.Request, p url.Values) (url.Values, signedIdentity, string) {
	id := p.Get("client_id")
	client, registered := s.Clients[id]
	if r.Method != http.MethodGet || p.Has("request") == p.Has("request_uri") || len(p) != 2 {
		return nil, signedIdentity{}, "invalid_request"
	}
	raw := p.Get("request")
	if p.Has("request_uri") {
		uri := p.Get("request_uri")
		if !registered || !metadataURL(uri) || !slices.Contains(client.RequestURIs, uri) {
			return nil, signedIdentity{}, "invalid_request_uri"
		}
		var err error
		raw, err = fetchRequestObject(r.Context(), s.requestObjects, uri)
		if err != nil {
			return nil, signedIdentity{}, "invalid_request_uri"
		}
	}
	values, identity, err := s.requestObject(raw, id, client)
	if err != nil {
		return nil, signedIdentity{}, "invalid_request_object"
	}
	return values, identity, ""
}

func (s Server) claimRequestObject(ctx context.Context, identity signedIdentity) (int, string) {
	err := s.claimSigned(ctx, "request-object", identity)
	switch {
	case errors.Is(err, errSignedJWT):
		return 400, "invalid_request_object"
	case err != nil:
		return 500, "server_error"
	default:
		return 0, ""
	}
}

// Bind the stored nonce to the session and exact authorization fields, using a
// namespace separate from public PAR references.
func signedConsentDigest(nonce, binding string) string {
	return store.Digest("jar-consent:" + nonce + ":" + binding)
}
