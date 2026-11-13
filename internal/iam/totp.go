package iam

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 default, what authenticator apps and Keycloak use
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"time"
)

// TOTP computes an RFC 6238 code (HMAC-SHA1, 30 s period, 6 digits by default).
//
// Keycloak uses the raw bytes of the stored OTP secret string as the HMAC key and shows
// their Base32 encoding to authenticator apps, so the lab passes the same string here.
func TOTP(secret []byte, t time.Time, period int64, digits int) string {
	if period <= 0 {
		period = 30
	}
	if digits <= 0 {
		digits = 6
	}
	return HOTP(secret, uint64(t.Unix()/period), digits)
}

// HOTP computes an RFC 4226 code.
func HOTP(secret []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, code%mod)
}

// Base32Secret is the form of the secret an authenticator app expects.
func Base32Secret(secret []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}
