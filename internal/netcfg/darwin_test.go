package netcfg

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/natesales/yk-wireguard/internal/config"
)

func TestPlanDarwinSpecificRoute(t *testing.T) {
	cfg, err := config.Parse(`
[Interface]
Address = 10.219.219.4/32

[Peer]
PublicKey = ` + config.EncodeKey(bytes32(9)) + `
Endpoint = 45.59.140.1:51295
AllowedIPs = 45.59.140.0/24
`)
	if err != nil {
		t.Fatal(err)
	}
	gw := netip.MustParseAddr("192.168.68.1")
	plan, err := PlanDarwin("utun4", cfg, []netip.Addr{netip.MustParseAddr("45.59.140.1")}, gw, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	joined := join(plan.Setup)
	for _, want := range []string{
		"ifconfig utun4 inet 10.219.219.4/32 10.219.219.4 alias",
		"route -q -n add -inet 45.59.140.1/32 -gateway 192.168.68.1",
		"route -q -n add -inet 45.59.140.0/24 -interface utun4",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "0.0.0.0/1") {
		t.Fatalf("specific route installed a default:\n%s", joined)
	}
	if !strings.Contains(join(plan.Cleanup), "route -q -n delete -inet 45.59.140.0/24 -interface utun4") {
		t.Fatalf("cleanup %v", plan.Cleanup)
	}
}

func TestPlanDarwinDefaultUsesHalves(t *testing.T) {
	cfg, err := config.Parse(`
[Interface]
Address = 10.8.0.2/32

[Peer]
PublicKey = ` + config.EncodeKey(bytes32(7)) + `
Endpoint = 203.0.113.5:51820
AllowedIPs = 0.0.0.0/0
`)
	if err != nil {
		t.Fatal(err)
	}
	ep := netip.MustParseAddr("203.0.113.5")
	gw := netip.MustParseAddr("192.168.68.1")
	plan, err := PlanDarwin("utun3", cfg, []netip.Addr{ep}, gw, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	joined := join(plan.Setup)
	for _, want := range []string{
		"route -q -n add -inet 203.0.113.5/32 -gateway 192.168.68.1",
		"route -q -n add -inet 0.0.0.0/1 -interface utun3",
		"route -q -n add -inet 128.0.0.0/1 -interface utun3",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q\n%s", want, joined)
		}
	}
}

func TestParseDarwinDefault(t *testing.T) {
	via, dev, ok := ParseDarwinDefault("   route to: default\ndestination: default\n    gateway: 192.168.68.1\n  interface: en0\n")
	if !ok || via.String() != "192.168.68.1" || dev != "en0" {
		t.Fatalf("%s %s %v", via, dev, ok)
	}
}
