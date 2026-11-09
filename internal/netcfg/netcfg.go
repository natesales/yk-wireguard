package netcfg

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/natesales/yk-wireguard/internal/config"
)

const table = 51820

// Plan is the address and route changes for one tunnel, plus the commands that undo them.
type Plan struct {
	Setup   [][]string
	Cleanup [][]string
}

// PlanRoutes builds wg-quick style addresses and routes.
// A default route is installed in a separate table so the tunnel's own UDP
// packets, marked with fwmark, stay on the existing gateway.
func PlanRoutes(iface string, cfg *config.Config, fwmark uint32, endpoints []netip.Addr, v4via netip.Addr, v4dev string, v6via netip.Addr, v6dev string) (Plan, error) {
	var plan Plan
	if cfg.MTU > 0 {
		plan.add(
			[]string{"ip", "link", "set", "dev", iface, "mtu", fmt.Sprint(cfg.MTU)},
			nil,
		)
	}
	plan.add([]string{"ip", "link", "set", "up", "dev", iface}, nil)
	for _, addr := range cfg.Addresses {
		plan.add(
			[]string{"ip", "addr", "add", addr.String(), "dev", iface},
			[]string{"ip", "addr", "del", addr.String(), "dev", iface},
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

	for _, peer := range cfg.Peers {
		for _, prefix := range peer.AllowedIPs {
			if prefix.Bits() == 0 {
				continue
			}
			plan.add(
				[]string{"ip", "route", "replace", prefix.String(), "dev", iface},
				[]string{"ip", "route", "del", prefix.String(), "dev", iface},
			)
		}
	}
	for _, ep := range endpoints {
		if !coveredBySpecific(cfg, ep) {
			continue
		}
		via, dev := v6via, v6dev
		host := ep.String() + "/128"
		family := "6"
		if ep.Is4() {
			via, dev = v4via, v4dev
			host = ep.String() + "/32"
			family = "4"
		}
		if !via.IsValid() || dev == "" {
			return Plan{}, fmt.Errorf("endpoint %s is inside an allowed ip, but there is no default route to keep the tunnel itself outside", ep)
		}
		plan.add(
			[]string{"ip", "-" + family, "route", "replace", host, "via", via.String(), "dev", dev},
			[]string{"ip", "-" + family, "route", "del", host, "via", via.String(), "dev", dev},
		)
	}

	mark := fmt.Sprint(fwmark)
	tbl := fmt.Sprint(table)
	if v4default {
		plan.addFamily("4", iface, mark, tbl, endpoints, v4via, v4dev, true)
	}
	if v6default {
		plan.addFamily("6", iface, mark, tbl, endpoints, v6via, v6dev, false)
	}
	return plan, nil
}

func coveredBySpecific(cfg *config.Config, ep netip.Addr) bool {
	for _, peer := range cfg.Peers {
		for _, prefix := range peer.AllowedIPs {
			if prefix.Bits() > 0 && prefix.Contains(ep) {
				return true
			}
		}
	}
	return false
}

func (p *Plan) addFamily(family, iface, mark, tbl string, endpoints []netip.Addr, via netip.Addr, dev string, v4 bool) {
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
		p.add(
			[]string{"ip", "-" + family, "route", "replace", host, "via", via.String(), "dev", dev},
			[]string{"ip", "-" + family, "route", "del", host, "via", via.String(), "dev", dev},
		)
	}
	p.add(
		[]string{"ip", "-" + family, "rule", "add", "not", "fwmark", mark, "table", tbl},
		[]string{"ip", "-" + family, "rule", "del", "not", "fwmark", mark, "table", tbl},
	)
	p.add(
		[]string{"ip", "-" + family, "rule", "add", "table", "main", "suppress_prefixlength", "0"},
		[]string{"ip", "-" + family, "rule", "del", "table", "main", "suppress_prefixlength", "0"},
	)
	p.add(
		[]string{"ip", "-" + family, "route", "replace", "default", "dev", iface, "table", tbl},
		[]string{"ip", "-" + family, "route", "del", "default", "dev", iface, "table", tbl},
	)
}

func (p *Plan) add(setup, cleanup []string) {
	if setup != nil {
		p.Setup = append(p.Setup, setup)
	}
	if cleanup != nil {
		p.Cleanup = append([][]string{cleanup}, p.Cleanup...)
	}
}

// ParseDefaultRoute reads `ip route show default` output.
func ParseDefaultRoute(out string) (via netip.Addr, dev string, ok bool) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "default" {
			continue
		}
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "via" {
				addr, err := netip.ParseAddr(fields[i+1])
				if err == nil {
					via = addr
				}
			}
			if fields[i] == "dev" {
				dev = fields[i+1]
			}
		}
		if via.IsValid() && dev != "" {
			return via, dev, true
		}
	}
	return netip.Addr{}, "", false
}
