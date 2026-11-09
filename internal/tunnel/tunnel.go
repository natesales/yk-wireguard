package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/natesales/yk-wireguard/internal/config"
	"github.com/natesales/yk-wireguard/internal/netcfg"
	"github.com/natesales/yk-wireguard/internal/openpgp"
)

// Options starts one userspace WireGuard interface.
type Options struct {
	Iface   string
	Config  *config.Config
	Card    *openpgp.Card
	Log     io.Writer
	Verbose bool
}

// Run holds the tunnel open until ctx is cancelled.
// The static private key stays on the YubiKey. Each handshake asks the card
// for one X25519 operation. Ephemeral keys stay in this process.
func Run(ctx context.Context, opts Options) error {
	if opts.Log == nil {
		opts.Log = io.Discard
	}
	key, err := opts.Card.Info()
	if err != nil {
		return fmt.Errorf("openpgp encryption slot: %w", err)
	}
	if !key.X25519 {
		if !key.HasKey {
			return fmt.Errorf("openpgp encryption slot is empty")
		}
		return fmt.Errorf("openpgp encryption slot does not hold an x25519 key")
	}
	if key.Touch != "never" {
		fmt.Fprintf(opts.Log, "openpgp touch policy is %s; a rekey every two minutes waits for that tap\n", key.Touch)
	}
	if err := opts.Card.Unlock(); err != nil {
		return err
	}

	iface, renamed := deviceName(opts.Iface)
	if renamed {
		fmt.Fprintf(opts.Log, "interface %s cannot be created on darwin; using utun\n", opts.Iface)
	}
	mtu := opts.Config.MTU
	if mtu == 0 {
		mtu = device.DefaultMTU
	}
	tdev, err := tun.CreateTUN(iface, mtu)
	if err != nil {
		return fmt.Errorf("create %s: %w", iface, err)
	}
	name, err := tdev.Name()
	if err != nil {
		tdev.Close()
		return err
	}

	level := device.LogLevelError
	if opts.Verbose {
		level = device.LogLevelVerbose
	}
	logger := device.NewLogger(level, fmt.Sprintf("(%s) ", name))
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)
	defer dev.Close()

	var public device.NoisePublicKey
	copy(public[:], key.Public[:])
	card := opts.Card
	err = dev.SetExternalStaticKey(public, func(peer device.NoisePublicKey) ([device.NoisePublicKeySize]byte, error) {
		secret, err := card.SharedSecret(peer[:])
		if err != nil {
			var zero [device.NoisePublicKeySize]byte
			return zero, err
		}
		var out [device.NoisePublicKeySize]byte
		copy(out[:], secret)
		return out, nil
	})
	if err != nil {
		return fmt.Errorf("install yubikey identity: %w", err)
	}

	fwmark := opts.Config.FwMark
	v4default, v6default := opts.Config.HasDefaultRoute()
	if !opts.Config.TableOff && (v4default || v6default) && fwmark == 0 {
		fwmark = 51820
	}
	if err := dev.IpcSet(opts.Config.UAPI(fwmark)); err != nil {
		return fmt.Errorf("apply config: %w", err)
	}
	if err := dev.Up(); err != nil {
		return fmt.Errorf("bring up %s: %w", name, err)
	}
	fmt.Fprintf(opts.Log, "%s up, public key %s, openpgp, firmware %s\n", name, config.EncodeKey(key.Public[:]), card.Version())
	if len(opts.Config.DNS) > 0 {
		fmt.Fprintf(opts.Log, "dns in the config is left alone: %s\n", strings.Join(opts.Config.DNS, ", "))
	}

	endpoints, err := resolveEndpoints(ctx, opts.Config)
	if err != nil {
		return err
	}
	var v4via, v6via netip.Addr
	var v4dev, v6dev string
	if !opts.Config.TableOff && (v4default || v6default || netcfg.CoversAny(opts.Config, endpoints)) {
		v4via, v4dev, v6via, v6dev, err = currentDefaults(ctx)
		if err != nil {
			return err
		}
	}
	var plan netcfg.Plan
	if runtime.GOOS == "darwin" {
		plan, err = netcfg.PlanDarwin(name, opts.Config, endpoints, v4via, v6via)
	} else {
		plan, err = netcfg.PlanRoutes(name, opts.Config, fwmark, endpoints, v4via, v4dev, v6via, v6dev)
	}
	if err != nil {
		return err
	}
	if err := runAll(ctx, plan.Setup); err != nil {
		_ = runAll(context.Background(), plan.Cleanup)
		return err
	}
	defer runAll(context.Background(), plan.Cleanup)

	<-ctx.Done()
	fmt.Fprintf(opts.Log, "stopping %s\n", name)
	return nil
}

func resolveEndpoints(ctx context.Context, cfg *config.Config) ([]netip.Addr, error) {
	var out []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, peer := range cfg.Peers {
		if peer.Endpoint == "" {
			continue
		}
		host, _, err := net.SplitHostPort(peer.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("endpoint %q: %w", peer.Endpoint, err)
		}
		if addr, err := netip.ParseAddr(host); err == nil {
			if !seen[addr] {
				out = append(out, addr)
				seen[addr] = true
			}
			continue
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", host, err)
		}
		for _, ip := range ips {
			if ip.Is4In6() {
				ip = netip.AddrFrom4(ip.As4())
			}
			if !seen[ip] {
				out = append(out, ip)
				seen[ip] = true
			}
		}
	}
	return out, nil
}

func currentDefaults(ctx context.Context) (netip.Addr, string, netip.Addr, string, error) {
	if runtime.GOOS == "darwin" {
		return darwinDefaults(ctx)
	}
	v4out, err := run(ctx, "ip", "-4", "route", "show", "default")
	if err != nil {
		return netip.Addr{}, "", netip.Addr{}, "", err
	}
	v4via, v4dev, _ := netcfg.ParseDefaultRoute(string(v4out))
	v6out, err := run(ctx, "ip", "-6", "route", "show", "default")
	if err != nil {
		return v4via, v4dev, netip.Addr{}, "", nil
	}
	v6via, v6dev, _ := netcfg.ParseDefaultRoute(string(v6out))
	return v4via, v4dev, v6via, v6dev, nil
}

func darwinDefaults(ctx context.Context) (netip.Addr, string, netip.Addr, string, error) {
	v4out, err := run(ctx, "route", "-n", "get", "-inet", "default")
	if err != nil {
		return netip.Addr{}, "", netip.Addr{}, "", err
	}
	v4via, v4dev, _ := netcfg.ParseDarwinDefault(string(v4out))
	v6out, err := run(ctx, "route", "-n", "get", "-inet6", "default")
	if err != nil {
		return v4via, v4dev, netip.Addr{}, "", nil
	}
	v6via, v6dev, _ := netcfg.ParseDarwinDefault(string(v6out))
	return v4via, v4dev, v6via, v6dev, nil
}

func deviceName(name string) (string, bool) {
	if runtime.GOOS != "darwin" || name == "utun" || isUtun(name) {
		return name, false
	}
	return "utun", true
}

func isUtun(name string) bool {
	rest, ok := strings.CutPrefix(name, "utun")
	if !ok || rest == "" {
		return false
	}
	for _, r := range rest {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func runAll(ctx context.Context, cmds [][]string) error {
	for _, cmd := range cmds {
		if _, err := run(ctx, cmd...); err != nil {
			return err
		}
	}
	return nil
}

func run(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s: %w: %s", strings.Join(args, " "), err, bytesTrim(out))
	}
	return out, nil
}

func bytesTrim(b []byte) string {
	return strings.TrimSpace(string(b))
}
