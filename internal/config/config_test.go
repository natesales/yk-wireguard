package config

import (
	"strings"
	"testing"
)

func TestParseAndUAPI(t *testing.T) {
	text := `
[Interface]
Address = 10.8.0.2/32, fd00::2/128
ListenPort = 51820
MTU = 1280
DNS = 1.1.1.1

[Peer]
PublicKey = YJBOCmL4F1Tss6k9y1p5b2mQ3vQh0n1k2l3m4n5o6p7=
PresharedKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Endpoint = vpn.example:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`
	// The public key above may not be valid base64 of 32 bytes. Build real keys.
	pub := EncodeKey(bytes32(1))
	psk := EncodeKey(bytes32(2))
	text = strings.ReplaceAll(text, "YJBOCmL4F1Tss6k9y1p5b2mQ3vQh0n1k2l3m4n5o6p7=", pub)
	text = strings.ReplaceAll(text, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", psk)

	cfg, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Addresses) != 2 || cfg.ListenPort != 51820 || cfg.MTU != 1280 {
		t.Fatalf("interface parsed wrong: %+v", cfg)
	}
	if len(cfg.DNS) != 1 || cfg.DNS[0] != "1.1.1.1" {
		t.Fatalf("dns %+v", cfg.DNS)
	}
	if len(cfg.Peers) != 1 || !cfg.Peers[0].HasPSK || cfg.Peers[0].Keepalive != 25 {
		t.Fatalf("peer %+v", cfg.Peers)
	}
	v4, v6 := cfg.HasDefaultRoute()
	if !v4 || !v6 {
		t.Fatalf("default routes v4=%v v6=%v", v4, v6)
	}
	uapi := cfg.UAPI(51820)
	for _, want := range []string{
		"listen_port=51820\n",
		"fwmark=51820\n",
		"replace_peers=true\n",
		"endpoint=vpn.example:51820\n",
		"allowed_ip=0.0.0.0/0\n",
		"allowed_ip=::/0\n",
		"persistent_keepalive_interval=25\n",
	} {
		if !strings.Contains(uapi, want) {
			t.Fatalf("uapi missing %q\n%s", want, uapi)
		}
	}
	if strings.Contains(uapi, "private_key=") {
		t.Fatal("uapi contains a private key")
	}
}

func TestRejectPrivateKey(t *testing.T) {
	_, err := Parse("[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n")
	if err == nil || !strings.Contains(err.Error(), "PrivateKey") {
		t.Fatal(err)
	}
}

func TestDecodeKeyPadding(t *testing.T) {
	raw := bytes32(9)
	padded := EncodeKey(raw)
	unpadded := strings.TrimRight(padded, "=")
	for _, s := range []string{padded, unpadded} {
		got, err := DecodeKey(s)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(raw[:]) {
			t.Fatalf("decode %s", s)
		}
	}
}

func bytes32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}
