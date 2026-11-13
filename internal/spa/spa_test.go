package spa

import (
	"context"
	"strings"
	"testing"
)

func validStanza(id, src string) Stanza {
	k, h := NewKeys()
	return Stanza{ID: id, Source: src, OpenPorts: []string{"tcp/8080"}, KeyBase64: k, HMACKeyBase64: h, AccessTimeout: 300}
}

func TestRenderAccessConf(t *testing.T) {
	b := validStanza("sess-b", "10.233.0.5")
	a := validStanza("sess-a", "ANY")
	a.OpenPorts = []string{"tcp/8443", "udp/53"}
	out, err := RenderAccessConf([]Stanza{b, a})
	if err != nil {
		t.Fatal(err)
	}
	ia, ib := strings.Index(out, "# sess-a"), strings.Index(out, "# sess-b")
	if ia < 0 || ib < 0 || ia > ib {
		t.Fatalf("stanzas missing or not sorted:\n%s", out)
	}
	for _, want := range []string{
		"SOURCE                  ANY\n",
		"SOURCE                  10.233.0.5\n",
		"OPEN_PORTS              tcp/8443,udp/53\n",
		"KEY_BASE64              " + a.KeyBase64 + "\n",
		"HMAC_KEY_BASE64         " + b.HMACKeyBase64 + "\n",
		"HMAC_DIGEST_TYPE        SHA256\n",
		"REQUIRE_SOURCE_ADDRESS  Y\n",
		"FW_ACCESS_TIMEOUT       300\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Count(out, "\nSOURCE") != 2 {
		t.Errorf("expected exactly 2 stanzas:\n%s", out)
	}
}

func TestRenderEmptyUsesPlaceholder(t *testing.T) {
	out, err := RenderAccessConf(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "SOURCE                  127.0.0.2") || strings.Count(out, "\nSOURCE") != 1 {
		t.Fatalf("placeholder stanza missing:\n%s", out)
	}
}

func TestStanzaValidationBlocksInjection(t *testing.T) {
	good := validStanza("s1", "10.0.0.1")
	bad := []func(*Stanza){
		func(s *Stanza) { s.ID = "x\nSOURCE ANY" },
		func(s *Stanza) { s.Source = "10.0.0.1\nOPEN_PORTS tcp/22" },
		func(s *Stanza) { s.Source = "example.com" },
		func(s *Stanza) { s.Source = "::1" },
		func(s *Stanza) { s.OpenPorts = []string{"tcp/22,tcp/23"} },
		func(s *Stanza) { s.OpenPorts = nil },
		func(s *Stanza) { s.KeyBase64 = "short" },
		func(s *Stanza) { s.HMACKeyBase64 = good.HMACKeyBase64 + "\nX Y" },
		func(s *Stanza) { s.AccessTimeout = 0 },
		// base64 decoding ignores newlines: the key itself must not carry any.
		func(s *Stanza) { s.KeyBase64 = good.KeyBase64[:8] + "\nSOURCE ANY\n" + good.KeyBase64[8:] },
	}
	for i, mutate := range bad {
		s := good
		s.OpenPorts = append([]string(nil), good.OpenPorts...)
		mutate(&s)
		if _, err := RenderAccessConf([]Stanza{s}); err == nil {
			t.Errorf("case %d: invalid stanza rendered", i)
		}
	}
	cidr := validStanza("s2", "10.233.0.0/24")
	if err := cidr.Validate(); err != nil {
		t.Errorf("CIDR source rejected: %v", err)
	}
}

func TestNewKeysAreRandom(t *testing.T) {
	k1, h1 := NewKeys()
	k2, h2 := NewKeys()
	if k1 == k2 || h1 == h2 || len(k1) != 44 || len(h1) != 88 {
		t.Fatalf("unexpected keys %q %q", k1, h1)
	}
}

func TestParseKeyFile(t *testing.T) {
	kf, err := ParseKeyFile([]byte("KEY_BASE64 abc\nHMAC_KEY_BASE64 def\n"))
	if err != nil || kf.KeyBase64 != "abc" || kf.HMACKeyBase64 != "def" {
		t.Fatalf("%v %+v", err, kf)
	}
	if _, err := ParseKeyFile([]byte("KEY_BASE64 abc\n")); err == nil {
		t.Fatal("missing HMAC key accepted")
	}
}

func TestRenderServerConfKeepsChains(t *testing.T) {
	c := RenderServerConf(DaemonConfig{Dir: "/var/lib/sdp/spa", Interface: "eth1", SPAPort: 62201, PcapLoopSleep: 10000}, 1)
	for _, want := range []string{"PCAP_INTF                   eth1;", "FLUSH_IPT_AT_INIT           N;",
		"FLUSH_IPT_AT_EXIT           N;", "FWKNOP_RUN_DIR              /var/lib/sdp/spa/run1;",
		"DIGEST_FILE                 /var/lib/sdp/spa/digest.cache;"} {
		if !strings.Contains(c, want) {
			t.Errorf("missing %q", want)
		}
	}
}

const listing = `-N FWKNOP_INPUT
-A FWKNOP_INPUT -s 10.233.0.5/32 -p tcp -m tcp --dport 8080 -m comment --comment _exp_1794563150 -j ACCEPT
-A FWKNOP_INPUT -s 10.233.0.50/32 -p tcp -m tcp --dport 8080 -m comment --comment _exp_1794563150 -j ACCEPT
-A FWKNOP_INPUT -s 10.233.0.5/32 -p tcp -m tcp --dport 9090 -m comment --comment _exp_1794563165 -j ACCEPT
`

func TestRulesForMatchesExactAddress(t *testing.T) {
	r := RulesFor(listing, "10.233.0.5")
	if len(r) != 2 || strings.Contains(r[0], "10.233.0.50") || strings.Contains(r[1], "10.233.0.50") {
		t.Fatalf("RulesFor = %v", r)
	}
}

func TestRemoveRulesFor(t *testing.T) {
	var calls []string
	fw := Firewall{Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "iptables" && len(args) == 3 && args[1] == "-S" {
			return []byte(listing), nil
		}
		return nil, nil
	}}
	n, err := fw.RemoveRulesFor(context.Background(), "10.233.0.5")
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	want := []string{
		"iptables -w -S FWKNOP_INPUT",
		"iptables -w -D FWKNOP_INPUT -s 10.233.0.5/32 -p tcp -m tcp --dport 8080 -m comment --comment _exp_1794563150 -j ACCEPT",
		"iptables -w -D FWKNOP_INPUT -s 10.233.0.5/32 -p tcp -m tcp --dport 9090 -m comment --comment _exp_1794563165 -j ACCEPT",
		"conntrack -D -s 10.233.0.5",
		"conntrack -D -d 10.233.0.5",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s", strings.Join(calls, "\n"))
	}
	if _, err := fw.RemoveRulesFor(context.Background(), "1.2.3.4; rm -rf /"); err == nil {
		t.Fatal("invalid ip accepted")
	}
}

func TestParseBytesSent(t *testing.T) {
	if n := parseBytesSent("...\nsend_spa_packet: bytes sent: 225\n"); n != 225 {
		t.Fatalf("got %d", n)
	}
	if n := parseBytesSent("nothing"); n != 0 {
		t.Fatalf("got %d", n)
	}
}
