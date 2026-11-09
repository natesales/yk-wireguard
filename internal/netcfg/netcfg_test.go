package netcfg

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/natesales/yk-wireguard/internal/config"
)

func TestPlanDefaultRouteExemptsEndpoint(t *testing.T) {
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
	gw := netip.MustParseAddr("192.0.2.1")
	plan, err := PlanRoutes("yk0", cfg, 51820, []netip.Addr{ep}, gw, "eth0", netip.Addr{}, "")
	if err != nil {
		t.Fatal(err)
	}
	joined := join(plan.Setup)
	for _, want := range []string{
		"ip addr add 10.8.0.2/32 dev yk0",
		"ip -4 route replace 203.0.113.5/32 via 192.0.2.1 dev eth0",
		"ip -4 rule add not fwmark 51820 table 51820",
		"ip -4 route replace default dev yk0 table 51820",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q\n%s", want, joined)
		}
	}
	if !strings.Contains(join(plan.Cleanup), "ip addr del 10.8.0.2/32 dev yk0") {
		t.Fatalf("cleanup %v", plan.Cleanup)
	}
}

func TestPlanRejectsDefaultWithoutGateway(t *testing.T) {
	cfg, err := config.Parse("[Interface]\nAddress = 10.8.0.2/32\n[Peer]\nPublicKey = " + config.EncodeKey(bytes32(3)) + "\nAllowedIPs = 0.0.0.0/0\n")
	if err != nil {
		t.Fatal(err)
	}
	_, err = PlanRoutes("yk0", cfg, 51820, nil, netip.Addr{}, "", netip.Addr{}, "")
	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestParseDefaultRoute(t *testing.T) {
	via, dev, ok := ParseDefaultRoute("default via 192.0.2.1 dev eth0 proto dhcp metric 100\n")
	if !ok || via.String() != "192.0.2.1" || dev != "eth0" {
		t.Fatalf("%s %s %v", via, dev, ok)
	}
}

func join(cmds [][]string) string {
	var b strings.Builder
	for _, c := range cmds {
		b.WriteString(strings.Join(c, " "))
		b.WriteByte('\n')
	}
	return b.String()
}

func bytes32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}
