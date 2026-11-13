package kernel

import (
	"crypto/rand"
	"encoding/hex"
)

// proxyAccount is a username/password pair for the socks/http inbound.
type proxyAccount struct{ User, Pass string }

// proxyAccounts maps panel accounts to socks/http credentials: username is the
// account email (e.g. "u42"), password is the account password (falling back to
// the id). These protocols have no "clients" concept and xray's http inbound
// (and sing-box's socks/http) become OPEN proxies when the account list is
// empty, so an empty list is replaced by one random, unguessable account to
// keep the inbound fail-closed.
func proxyAccounts(users []UserSpec) []proxyAccount {
	out := make([]proxyAccount, 0, len(users))
	for _, u := range users {
		name := u.Email
		if name == "" {
			name = "user"
		}
		pw := u.Password
		if pw == "" {
			pw = u.ID
		}
		if pw == "" {
			continue
		}
		out = append(out, proxyAccount{User: name, Pass: pw})
	}
	if len(out) == 0 {
		var a, b [16]byte
		_, _ = rand.Read(a[:])
		_, _ = rand.Read(b[:])
		out = append(out, proxyAccount{User: "locked-" + hex.EncodeToString(a[:]), Pass: hex.EncodeToString(b[:])})
	}
	return out
}
