package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/natesales/yk-wireguard/internal/config"
	"github.com/natesales/yk-wireguard/internal/openpgp"
	"github.com/natesales/yk-wireguard/internal/tunnel"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "pubkey":
		err = pubkey(os.Args[2:])
	case "up":
		err = up(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "yk-wireguard: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `yk-wireguard keeps a WireGuard identity on a YubiKey.

The X25519 private key is generated on the card. wireguard-go asks the card
for the static Diffie-Hellman on each handshake. Ephemeral keys stay in
this process. The rest of the tunnel config stays in a normal wg-quick file,
which must not contain PrivateKey.

The key lives in the OpenPGP encryption slot. That needs YubiKey firmware
5.2.3 or later, which is when the applet can generate an X25519 key and
return the raw shared secret.

Usage:
  yk-wireguard keygen
  yk-wireguard pubkey
  yk-wireguard up --config FILE [--iface NAME] [-v]
`)
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	serial := fs.Uint("serial", 0, "YubiKey serial, when more than one is plugged in")
	admin := fs.String("admin-pin", "", "OpenPGP admin PIN, or prompt when omitted")
	force := fs.Bool("force", false, "replace the OpenPGP encryption key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	card, err := openpgp.Open(uint32(*serial))
	if err != nil {
		return err
	}
	defer card.Close()

	info, err := card.Info()
	if err != nil {
		return err
	}
	if info.HasKey && !*force {
		return fmt.Errorf("openpgp encryption slot already holds a key; pass --force to replace it, which deletes the gpg encryption key")
	}

	adminPIN := *admin
	if adminPIN == "" {
		adminPIN, err = promptPIN("OpenPGP admin PIN")
		if err != nil {
			return err
		}
	}
	pub, err := card.Generate(adminPIN)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, config.EncodeKey(pub[:]))
	fmt.Fprintf(os.Stderr, "serial %d firmware %s\n", card.Serial(), card.Version())
	return nil
}

func pubkey(args []string) error {
	fs := flag.NewFlagSet("pubkey", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	serial := fs.Uint("serial", 0, "YubiKey serial")
	if err := fs.Parse(args); err != nil {
		return err
	}
	card, err := openpgp.Open(uint32(*serial))
	if err != nil {
		return err
	}
	defer card.Close()
	info, err := card.Info()
	if err != nil {
		return err
	}
	if !info.X25519 {
		if !info.HasKey {
			return fmt.Errorf("openpgp encryption slot is empty")
		}
		return fmt.Errorf("openpgp encryption slot does not hold an x25519 key")
	}
	fmt.Fprintln(os.Stdout, config.EncodeKey(info.Public[:]))
	return nil
}

func up(args []string) error {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "", "wg-quick config without PrivateKey")
	iface := fs.String("iface", "", "interface name (default: config file name)")
	serial := fs.Uint("serial", 0, "YubiKey serial")
	pinFlag := fs.String("pin", "", "OpenPGP user PIN, or prompt")
	verbose := fs.Bool("v", false, "log wireguard debug output")
	fs.BoolVar(verbose, "verbose", false, "log wireguard debug output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *configPath == "" {
		return fmt.Errorf("up requires --config")
	}
	raw, err := os.ReadFile(*configPath)
	if err != nil {
		return err
	}
	cfg, err := config.Parse(string(raw))
	if err != nil {
		return err
	}
	name := *iface
	if name == "" {
		name = ifaceFromPath(*configPath)
	}
	card, err := openpgp.Open(uint32(*serial))
	if err != nil {
		return err
	}
	defer card.Close()
	fmt.Fprintf(os.Stderr, "serial %d firmware %s\n", card.Serial(), card.Version())
	if err := card.UsePIN(*pinFlag, func() (string, error) {
		return promptPIN("OpenPGP user PIN")
	}); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return tunnel.Run(ctx, tunnel.Options{
		Iface:   name,
		Config:  cfg,
		Card:    card,
		Log:     os.Stderr,
		Verbose: *verbose,
	})
}

func promptPIN(label string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s: ", label)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(pw), nil
}

func ifaceFromPath(path string) string {
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	var b strings.Builder
	for _, r := range base {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	name := b.String()
	if name == "" {
		return "yk0"
	}
	if len(name) > 15 {
		name = name[:15]
	}
	return name
}
