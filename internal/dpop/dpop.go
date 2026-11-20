package dpop

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/cuhawk/BastionAuth/internal/joseutil"
	"github.com/cuhawk/BastionAuth/internal/store"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

var ErrProof = errors.New("invalid DPoP proof")

const Window = 60 * time.Second

type Verifier struct {
	Store store.Store
	Now   func() time.Time
}
type claims struct {
	jwt.Claims
	Method string `json:"htm"`
	URI    string `json:"htu"`
	Hash   string `json:"ath"`
}

func (v Verifier) Verify(ctx context.Context, tenant, proof, method, target, accessToken, binding string) (string, error) {
	if len(proof) > 8192 || strings.Count(proof, ".") != 2 {
		return "", ErrProof
	}
	token, err := jwt.ParseSigned(proof, joseutil.Algorithms)
	if err != nil || len(token.Headers) != 1 {
		return "", ErrProof
	}
	header := token.Headers[0]
	key := header.JSONWebKey
	if header.ExtraHeaders[jose.HeaderType] != "dpop+jwt" || key == nil || !key.Valid() || !key.IsPublic() || !joseutil.Matches(header.Algorithm, key.Key) || (key.Algorithm != "" && key.Algorithm != header.Algorithm) {
		return "", ErrProof
	}
	var c claims
	if err := token.Claims(key.Key, &c); err != nil {
		return "", ErrProof
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	if c.IssuedAt == nil || c.ID == "" || len(c.ID) > 256 || c.Method != method || c.IssuedAt.Time().Before(now.Add(-Window)) || c.IssuedAt.Time().After(now.Add(Window)) {
		return "", ErrProof
	}
	actual, err := normalize(target)
	if err != nil {
		return "", ErrProof
	}
	presented, err := normalize(c.URI)
	if err != nil || strings.ContainsAny(c.URI, "?#") || actual != presented {
		return "", ErrProof
	}
	if accessToken != "" && subtle.ConstantTimeCompare([]byte(c.Hash), []byte(store.Digest(accessToken))) != 1 {
		return "", ErrProof
	}
	if accessToken == "" && c.Hash != "" {
		return "", ErrProof
	}
	jkt, err := joseutil.Thumbprint(*key)
	if err != nil || (binding != "" && subtle.ConstantTimeCompare([]byte(jkt), []byte(binding)) != 1) {
		return "", ErrProof
	}
	claimed, err := v.Store.ClaimProof(ctx, tenant, jkt, c.ID, now, c.IssuedAt.Time().Add(Window+time.Second))
	if err != nil {
		return "", err
	}
	if !claimed {
		return "", ErrProof
	}
	return jkt, nil
}

func normalize(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Hostname() == "" || u.Opaque != "" {
		return "", ErrProof
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", ErrProof
	}
	host, port := strings.ToLower(u.Hostname()), u.Port()
	if port != "" && !((scheme == "https" && port == "443") || (scheme == "http" && port == "80")) {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + normalizePath(path), nil
}

// Decode unreserved octets and remove dot segments without collapsing empty segments.
func normalizePath(path string) string {
	const hex = "0123456789ABCDEF"
	var out strings.Builder
	for i := 0; i < len(path); i++ {
		if path[i] != '%' {
			out.WriteByte(path[i])
			continue
		}
		high := strings.IndexByte(hex, upper(path[i+1]))
		low := strings.IndexByte(hex, upper(path[i+2]))
		b := byte(high*16 + low)
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || strings.ContainsRune("-._~", rune(b)) {
			out.WriteByte(b)
		} else {
			out.WriteByte('%')
			out.WriteByte(hex[high])
			out.WriteByte(hex[low])
		}
		i += 2
	}
	parts := strings.Split(out.String(), "/")
	stack := make([]string, 0, len(parts))
	for i, part := range parts[1:] {
		switch part {
		case "..":
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			if i == len(parts)-2 {
				stack = append(stack, "")
			}
		case ".":
			if i == len(parts)-2 {
				stack = append(stack, "")
			}
		default:
			stack = append(stack, part)
		}
	}
	return "/" + strings.Join(stack, "/")
}

func upper(b byte) byte {
	if b >= 'a' && b <= 'f' {
		return b - 32
	}
	return b
}
