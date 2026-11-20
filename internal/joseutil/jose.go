package joseutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"

	jose "github.com/go-jose/go-jose/v4"
)

var Algorithms = []jose.SignatureAlgorithm{jose.EdDSA, jose.ES256, jose.RS256}

func Matches(algorithm string, key any) bool {
	switch k := key.(type) {
	case ed25519.PublicKey:
		return algorithm == string(jose.EdDSA) && len(k) == ed25519.PublicKeySize
	case *ecdsa.PublicKey:
		return algorithm == string(jose.ES256) && k.Curve == elliptic.P256()
	case *rsa.PublicKey:
		return algorithm == string(jose.RS256) && k.N.BitLen() >= 2048
	}
	return false
}

func Thumbprint(key jose.JSONWebKey) (string, error) {
	hash, err := key.Thumbprint(crypto.SHA256)
	return base64.RawURLEncoding.EncodeToString(hash), err
}
