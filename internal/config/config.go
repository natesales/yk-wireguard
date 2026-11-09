package config

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Config is a wg-quick file without a local private key.
type Config struct {
	Addresses  []netip.Prefix
	ListenPort uint16
	MTU        int
	DNS        []string
	TableOff   bool
	FwMark     uint32
	Peers      []Peer
}

// Peer is one remote WireGuard peer.
type Peer struct {
	PublicKey    [32]byte
	PresharedKey [32]byte
	HasPSK       bool
	Endpoint     string
	AllowedIPs   []netip.Prefix
	Keepalive    uint16
}

// Parse reads a wg-quick configuration. PrivateKey is rejected.
func Parse(text string) (*Config, error) {
	cfg := &Config{}
	var section string
	var peer *Peer
	lineNo := 0
	sc := bufio.NewScanner(bytes.NewBufferString(text))
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			if peer != nil {
				cfg.Peers = append(cfg.Peers, *peer)
				peer = nil
			}
			section = strings.ToLower(line[1 : len(line)-1])
			if section == "peer" {
				peer = &Peer{}
			} else if section != "interface" {
				return nil, fmt.Errorf("line %d: unknown section %s", lineNo, section)
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected key = value", lineNo)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if i := strings.Index(value, "#"); i >= 0 {
			value = strings.TrimSpace(value[:i])
		}
		switch section {
		case "interface":
			if err := cfg.setInterface(lineNo, key, value); err != nil {
				return nil, err
			}
		case "peer":
			if peer == nil {
				return nil, fmt.Errorf("line %d: key outside a section", lineNo)
			}
			if err := peer.set(lineNo, key, value); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("line %d: key outside a section", lineNo)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if peer != nil {
		cfg.Peers = append(cfg.Peers, *peer)
	}
	for i, p := range cfg.Peers {
		var zero [32]byte
		if p.PublicKey == zero {
			return nil, fmt.Errorf("peer %d is missing PublicKey", i+1)
		}
	}
	return cfg, nil
}

func (c *Config) setInterface(line int, key, value string) error {
	switch key {
	case "privatekey":
		return fmt.Errorf("line %d: PrivateKey is the x25519 key on the yubikey, remove it from the config", line)
	case "address":
		prefixes, err := parsePrefixes(value)
		if err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
		c.Addresses = append(c.Addresses, prefixes...)
	case "listenport":
		n, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return fmt.Errorf("line %d: ListenPort: %w", line, err)
		}
		c.ListenPort = uint16(n)
	case "mtu":
		n, err := strconv.Atoi(value)
		if err != nil || n < 576 {
			return fmt.Errorf("line %d: MTU %q", line, value)
		}
		c.MTU = n
	case "dns":
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				c.DNS = append(c.DNS, part)
			}
		}
	case "table":
		if strings.EqualFold(value, "off") {
			c.TableOff = true
		} else {
			return fmt.Errorf("line %d: Table %q is unsupported (use off, or omit it)", line, value)
		}
	case "fwmark":
		n, err := strconv.ParseUint(value, 0, 32)
		if err != nil {
			return fmt.Errorf("line %d: FwMark: %w", line, err)
		}
		c.FwMark = uint32(n)
	default:
		return fmt.Errorf("line %d: unknown interface key %s", line, key)
	}
	return nil
}

func (p *Peer) set(line int, key, value string) error {
	switch key {
	case "publickey":
		raw, err := DecodeKey(value)
		if err != nil {
			return fmt.Errorf("line %d: PublicKey: %w", line, err)
		}
		copy(p.PublicKey[:], raw)
	case "presharedkey":
		raw, err := DecodeKey(value)
		if err != nil {
			return fmt.Errorf("line %d: PresharedKey: %w", line, err)
		}
		copy(p.PresharedKey[:], raw)
		p.HasPSK = true
	case "endpoint":
		p.Endpoint = value
	case "allowedips":
		prefixes, err := parsePrefixes(value)
		if err != nil {
			return fmt.Errorf("line %d: %w", line, err)
		}
		p.AllowedIPs = append(p.AllowedIPs, prefixes...)
	case "persistentkeepalive":
		n, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return fmt.Errorf("line %d: PersistentKeepalive: %w", line, err)
		}
		p.Keepalive = uint16(n)
	default:
		return fmt.Errorf("line %d: unknown peer key %s", line, key)
	}
	return nil
}

func parsePrefixes(value string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			addr, err := netip.ParseAddr(part)
			if err != nil {
				return nil, fmt.Errorf("address %q", part)
			}
			bits := 32
			if addr.Is6() {
				bits = 128
			}
			part = fmt.Sprintf("%s/%d", addr, bits)
		}
		prefix, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("prefix %q", part)
		}
		out = append(out, prefix.Masked())
	}
	return out, nil
}

// DecodeKey parses a standard or unpadded base64 WireGuard key.
func DecodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		raw, err := enc.DecodeString(s)
		if err == nil && len(raw) == 32 {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("expected 32 bytes in base64")
}

// EncodeKey formats a WireGuard key the way wg does, with padding.
func EncodeKey(raw []byte) string {
	return base64.StdEncoding.EncodeToString(raw)
}

// UAPI is the wireguard-go configuration, without a private key.
// fwmark is included when non-zero.
func (c *Config) UAPI(fwmark uint32) string {
	var b strings.Builder
	if c.ListenPort != 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", c.ListenPort)
	}
	mark := fwmark
	if mark == 0 {
		mark = c.FwMark
	}
	if mark != 0 {
		fmt.Fprintf(&b, "fwmark=%d\n", mark)
	}
	b.WriteString("replace_peers=true\n")
	for _, peer := range c.Peers {
		fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(peer.PublicKey[:]))
		if peer.HasPSK {
			fmt.Fprintf(&b, "preshared_key=%s\n", hex.EncodeToString(peer.PresharedKey[:]))
		}
		if peer.Endpoint != "" {
			fmt.Fprintf(&b, "endpoint=%s\n", peer.Endpoint)
		}
		if peer.Keepalive != 0 {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", peer.Keepalive)
		}
		b.WriteString("replace_allowed_ips=true\n")
		for _, prefix := range peer.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", prefix)
		}
	}
	return b.String()
}

// HasDefaultRoute reports whether any peer claims 0.0.0.0/0 or ::/0.
func (c *Config) HasDefaultRoute() (v4, v6 bool) {
	for _, peer := range c.Peers {
		for _, prefix := range peer.AllowedIPs {
			if prefix.Bits() == 0 {
				if prefix.Addr().Is4() {
					v4 = true
				} else {
					v6 = true
				}
			}
		}
	}
	return v4, v6
}
