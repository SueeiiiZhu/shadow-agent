package kernel

import "encoding/json"

// Hysteria2 accepts YAML or JSON; we emit JSON (valid YAML subset) using only
// the standard library. Auth uses the userpass map keyed by email->password,
// falling back to the first user's password as a shared secret.
func marshalHysteria2(spec *NodeSpec) ([]byte, string, error) {
	listen := spec.EffectiveListen()
	cfg := map[string]any{
		"listen": listenAddr(listen, spec.Port),
	}

	// TLS: use provided cert/key files when available.
	if spec.Stream != nil && spec.Stream.TLS != nil &&
		(spec.Stream.TLS.CertFile != "" || spec.Stream.TLS.KeyFile != "") {
		cfg["tls"] = map[string]any{
			"cert": spec.Stream.TLS.CertFile,
			"key":  spec.Stream.TLS.KeyFile,
		}
	}

	// Authentication: per-user password map.
	userpass := map[string]any{}
	for _, u := range spec.Users {
		key := u.Email
		if key == "" {
			key = u.ID
		}
		if key != "" {
			userpass[key] = u.Password
		}
	}
	auth := map[string]any{"type": "userpass", "userpass": userpass}
	if len(userpass) == 0 && len(spec.Users) > 0 {
		auth = map[string]any{"type": "password", "password": spec.Users[0].Password}
	}
	cfg["auth"] = auth

	// Outbound / upstream proxy: Hysteria2 supports SOCKS5 / HTTP outbounds.
	if ob := hysteria2Outbound(spec); ob != nil {
		cfg["outbounds"] = ob
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, "", err
	}
	return data, "yaml", nil
}

func hysteria2Outbound(spec *NodeSpec) []any {
	if spec.Outbound == nil {
		return nil
	}
	o := spec.Outbound
	tag := o.Tag
	if tag == "" {
		tag = "proxy"
	}
	switch o.Protocol {
	case "socks":
		entry := map[string]any{"addr": listenAddr(o.Address, o.Port)}
		if o.User != "" {
			entry["username"] = o.User
		}
		if o.Pass != "" {
			entry["password"] = o.Pass
		}
		return []any{map[string]any{"name": tag, "type": "socks5", "socks5": entry}}
	case "http":
		entry := map[string]any{"url": httpProxyURL(o)}
		return []any{map[string]any{"name": tag, "type": "http", "http": entry}}
	default:
		return nil
	}
}
