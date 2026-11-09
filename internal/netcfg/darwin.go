package netcfg

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/natesales/yk-wireguard/internal/config"
)

// PlanDarwin builds addresses and routes with ifconfig and route.
// Darwin has no policy routing, so a default route is two /1 prefixes and the
// WireGuard endpoint stays on the current gateway.
func PlanDarwin(iface string, cfg *config.Config, endpoints []netip.Addr, v4via, v6via netip.Addr) (Plan, error) {
	var plan Plan
	if cfg.MTU > 0 {
		plan.add([]string{"ifconfig", iface, "mtu", fmt.Sprint(cfg.MTU)}, nil)
	}
	for _, addr := range cfg.Addresses {
		if addr.Addr().Is4() {
			plan.add(
				[]string{"ifconfig", iface, "inet", addr.String(), addr.Addr().String(), "alias"},
				[]string{"ifconfig", iface, "inet", addr.String(), addr.Addr().String(), "-alias"},
			)
			continue
		}
		plan.add(
			[]string{"ifconfig", iface, "inet6", addr.String(), "alias"},
			[]string{"ifconfig", iface, "inet6", addr.String(), "-alias"},
		)
	}
	if cfg.TableOff {
		return plan, nil
	}

	v4default, v6default := cfg.HasDefaultRoute()
	if v4default && !v4via.IsValid() {
		return Plan{}, fmt.Errorf("allowed ips include 0.0.0.0/0 but there is no ipv4 default route to exempt the wireguard endpoint")
	}
	if v6default && !v6via.IsValid() {
		return Plan{}, fmt.Errorf("allowed ips include ::/0 but there is no ipv6 default route to exempt the wireguard endpoint")
	}
	if err := plan.exempt(cfg, endpoints, v4via, v6via); err != nil {
		return Plan{}, err
	}
	if v4default {
		plan.route("inet", "0.0.0.0/1", iface)
		plan.route("inet", "128.0.0.0/1", iface)
	}
	if v6default {
		plan.route("inet6", "::/1", iface)
		plan.route("inet6", "8000::/1", iface)
	}
	for _, peer := range cfg.Peers {
		for _, prefix := range peer.AllowedIPs {
			if prefix.Bits() == 0 {
				continue
			}
			family := "inet"
			if prefix.Addr().Is6() {
				family = "inet6"
			}
			plan.route(family, prefix.String(), iface)
		}
	}
	return plan, nil
}

// CoversAny reports whether any endpoint is inside an AllowedIP.
func CoversAny(cfg *config.Config, endpoints []netip.Addr) bool {
	for _, ep := range endpoints {
		if Covers(cfg, ep) {
			return true
		}
	}
	return false
}

// Covers reports whether ep is inside an AllowedIP. Those packets are routed
// into the tunnel, so the peer endpoint needs a more specific route outside it.
func Covers(cfg *config.Config, ep netip.Addr) bool {
	for _, peer := range cfg.Peers {
		for _, prefix := range peer.AllowedIPs {
			if prefix.Contains(ep) {
				return true
			}
		}
	}
	return false
}

func (p *Plan) exempt(cfg *config.Config, endpoints []netip.Addr, v4via, v6via netip.Addr) error {
	for _, ep := range endpoints {
		if !Covers(cfg, ep) {
			continue
		}
		via := v6via
		v4 := false
		if ep.Is4() {
			via = v4via
			v4 = true
		}
		if !via.IsValid() {
			return fmt.Errorf("endpoint %s is inside an allowed ip, but there is no default route to keep the tunnel itself outside", ep)
		}
		p.endpointVia([]netip.Addr{ep}, via, v4)
	}
	return nil
}

func (p *Plan) endpointVia(endpoints []netip.Addr, via netip.Addr, v4 bool) {
	for _, ep := range endpoints {
		if ep.Is4() != v4 {
			continue
		}
		host := ep.String()
		if v4 {
			host += "/32"
		} else {
			host += "/128"
		}
		family := "inet6"
		if v4 {
			family = "inet"
		}
		p.add(
			[]string{"route", "-q", "-n", "add", "-" + family, host, "-gateway", via.String()},
			[]string{"route", "-q", "-n", "delete", "-" + family, host, "-gateway", via.String()},
		)
	}
}

func (p *Plan) route(family, prefix, iface string) {
	p.add(
		[]string{"route", "-q", "-n", "add", "-" + family, prefix, "-interface", iface},
		[]string{"route", "-q", "-n", "delete", "-" + family, prefix, "-interface", iface},
	)
}

// ParseDarwinDefault reads `route -n get default`.
func ParseDarwinDefault(out string) (via netip.Addr, dev string, ok bool) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "gateway:":
			addr, err := netip.ParseAddr(fields[1])
			if err == nil {
				via = addr
			}
		case "interface:":
			dev = fields[1]
		}
	}
	return via, dev, via.IsValid() && dev != ""
}
