package kernel

import (
	"fmt"
	"net/url"
	"strings"
)

// NaiveProxy runs as a Caddy server with the forward_proxy directive. We emit a
// Caddyfile. Auth is basic user:pass pairs from the user list (email as user,
// password as secret).
func marshalNaive(spec *NodeSpec) ([]byte, string, error) {
	var b strings.Builder

	sni := "example.com"
	if spec.Stream != nil && spec.Stream.TLS != nil && spec.Stream.TLS.SNI != "" {
		sni = spec.Stream.TLS.SNI
	}

	// Site address: bind on the configured port for the SNI host.
	fmt.Fprintf(&b, "%s:%d {\n", sni, spec.Port)

	// TLS: explicit cert/key if provided, otherwise rely on Caddy automation.
	if spec.Stream != nil && spec.Stream.TLS != nil &&
		spec.Stream.TLS.CertFile != "" && spec.Stream.TLS.KeyFile != "" {
		fmt.Fprintf(&b, "\ttls %s %s\n", spec.Stream.TLS.CertFile, spec.Stream.TLS.KeyFile)
	}

	b.WriteString("\troute {\n")
	b.WriteString("\t\tforward_proxy {\n")
	b.WriteString("\t\t\tbasic_auth_in_header off\n")
	for _, u := range spec.Users {
		user := u.Email
		if user == "" {
			user = u.ID
		}
		if user != "" {
			fmt.Fprintf(&b, "\t\t\tbasic_auth %s %s\n", user, u.Password)
		}
	}
	b.WriteString("\t\t\thide_ip\n")
	b.WriteString("\t\t\thide_via\n")
	b.WriteString("\t\t\tprobe_resistance\n")
	b.WriteString("\t\t}\n")
	b.WriteString("\t}\n")
	b.WriteString("}\n")

	return []byte(b.String()), "Caddyfile", nil
}

// httpProxyURL builds an http(s) proxy URL with optional credentials. Shared by
// kernels that express http outbounds as a URL.
func httpProxyURL(o *OutboundSpec) string {
	scheme := "http"
	if o.Security == "tls" || o.Security == "https" {
		scheme = "https"
	}
	host := fmt.Sprintf("%s:%d", o.Address, o.Port)
	if o.User != "" || o.Pass != "" {
		u := url.UserPassword(o.User, o.Pass)
		return fmt.Sprintf("%s://%s@%s", scheme, u.String(), host)
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}

// listenAddr joins a host and port, defaulting host to 0.0.0.0 when empty.
func listenAddr(host string, port int) string {
	if host == "" {
		host = "0.0.0.0"
	}
	return fmt.Sprintf("%s:%d", host, port)
}
