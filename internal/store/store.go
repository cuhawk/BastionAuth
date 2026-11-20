package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"
)

var ErrInvalid = errors.New("invalid grant")

type Credential struct {
	User, Client, Kind, Redirect, Challenge, Scope, JKT string
	AuthorizationDetails                                string `json:",omitempty"`
	Expires                                             time.Time
}

type Store interface {
	SavePushedRequest(context.Context, string, string, PushedRequest) error
	TakePushedRequest(context.Context, string, string, string) (string, error)
	Consent(context.Context, string, string, Credential) error
	Revoke(context.Context, string, string, string) error
	Rotate(context.Context, string, string, string, func(Credential) (Credential, error)) error
	ClaimProof(context.Context, string, string, string, time.Time, time.Time) (bool, error)
}

func Secret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func Digest(value string) string {
	hash := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
