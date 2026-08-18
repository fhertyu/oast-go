// Package token generates random OAST callback tokens and manages their
// lifecycle against the in-memory Store.
package token

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/oast/oast/internal/storage"
)

// alphabet is a 32-symbol set with visually ambiguous characters removed
// (no 0/O/1/I/L). Each symbol carries 5 bits of entropy.
const alphabet = "23456789abcdefghjkmnpqrstuvwxyz"

// tokenLen is the number of alphabet symbols in a token. 8 chars = 40 bits of
// entropy; collisions are retried by the caller (see Manager.Create / the API
// handler) so the shorter subdomain stays safe.
const tokenLen = 8

// Generate returns a new random token string of 8 chars (40 bits entropy).
// It uses crypto/rand with rejection sampling to avoid modulo bias.
func Generate() (string, error) {
	const n = len(alphabet)          // 32
	const valueSpace = 256           // byte range
	reject := valueSpace - (valueSpace % n) // == 256 when n divides 256 (32 does)

	out := make([]byte, tokenLen)
	buf := make([]byte, tokenLen)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	for i := 0; i < tokenLen; i++ {
		v := int(buf[i])
		for v >= reject {
			if _, err := rand.Read(buf[i : i+1]); err != nil {
				return "", err
			}
			v = int(buf[i])
		}
		out[i] = alphabet[v%n]
	}
	return string(out), nil
}

// Validate returns nil if v looks like a generated token. It only checks shape,
// not existence (existence is checked against the Store).
func Validate(v string) error {
	if len(v) != tokenLen {
		return fmt.Errorf("token must be %d chars, got %d", tokenLen, len(v))
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !isAlphabet(c) {
			return fmt.Errorf("invalid char %q in token", c)
		}
	}
	return nil
}

func isAlphabet(c byte) bool {
	for i := 0; i < len(alphabet); i++ {
		if alphabet[i] == c {
			return true
		}
	}
	return false
}

// ErrEmpty is returned when generation could not produce a unique token.
var ErrEmpty = errors.New("empty token")

// MatchToken resolves the token label inside a query-name prefix and any
// client-exfiltrated data labels (data lives on either side of the token):
//
//	root.xxx.123.xyz   -> data=["root"],     token="xxx"
//	xxx.123.xyz        -> data=nil,          token="xxx"   (no data)
//	xxx.root.123.xyz   -> data=["root"],     token="xxx"   (token first)
//	root.user.xxx.xyz  -> data=["root","user"], token="xxx"
//
// It scans right-to-left (closest to the zone) and uses the first label that
// is a registered token; everything else in the prefix is kept as data (in
// original order). If nothing registers, the label bordering the zone is the
// best guess for a token (handles the token.domain case).
func MatchToken(ctx context.Context, st storage.Store, prefix []string) (tokenValue string, data []string) {
	if len(prefix) == 0 {
		return "", nil
	}
	if len(prefix) == 1 {
		return prefix[0], nil
	}
	tokenIdx := -1
	for i := len(prefix) - 1; i >= 0; i-- {
		if _, err := st.GetTokenByValue(ctx, prefix[i]); err == nil {
			tokenIdx = i
			break
		}
	}
	if tokenIdx < 0 {
		tokenIdx = len(prefix) - 1 // fallback: zone-bordering label
	}
	data = make([]string, 0, len(prefix)-1)
	for i, l := range prefix {
		if i != tokenIdx {
			data = append(data, l)
		}
	}
	return prefix[tokenIdx], data
}
