package kernel

import "testing"

func TestXraySocksHTTPInbound(t *testing.T) {
	for _, proto := range []string{"socks", "http"} {
		spec := &NodeSpec{Tag: "p", Kernel: "xray", Protocol: proto, Port: 1080,
			Users: []UserSpec{{Email: "u1", Password: "pw1"}, {Email: "u2", ID: "id2"}}}
		in, err := buildXrayBusinessInbound(spec)
		if err != nil {
			t.Fatal(err)
		}
		st := in["settings"].(map[string]any)
		accts := st["accounts"].([]map[string]any)
		if len(accts) != 2 || accts[0]["user"] != "u1" || accts[0]["pass"] != "pw1" || accts[1]["pass"] != "id2" {
			t.Fatalf("%s accounts = %v", proto, accts)
		}
		if proto == "socks" && st["auth"] != "password" {
			t.Fatal("socks must require password auth")
		}
	}
}

// With no active users the inbound must NOT become an open proxy.
func TestProxyInboundFailsClosedWithoutUsers(t *testing.T) {
	a := proxyAccounts(nil)
	b := proxyAccounts(nil)
	if len(a) != 1 || a[0].Pass == "" || a[0].User == "" {
		t.Fatalf("no placeholder account: %v", a)
	}
	if a[0].Pass == b[0].Pass {
		t.Fatal("placeholder credentials must be random")
	}
	in, err := singboxInbound(&NodeSpec{Tag: "p", Protocol: "socks", Port: 1080})
	if err != nil {
		t.Fatal(err)
	}
	if u := in["users"].([]map[string]any); len(u) != 1 {
		t.Fatalf("singbox users = %v", u)
	}
}

func TestSingboxSocksHTTPInbound(t *testing.T) {
	in, err := singboxInbound(&NodeSpec{Tag: "p", Protocol: "http", Port: 8080, Users: []UserSpec{{Email: "u1", Password: "pw"}}})
	if err != nil {
		t.Fatal(err)
	}
	u := in["users"].([]map[string]any)[0]
	if in["type"] != "http" || u["username"] != "u1" || u["password"] != "pw" {
		t.Fatalf("inbound = %v", in)
	}
}
