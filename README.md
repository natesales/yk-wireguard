# yk-wireguard

Userspace WireGuard backed by a YubiKey. The X25519 key is generated on the card and stays there. `wireguard-go` asks the card for the static Diffie-Hellman on each handshake.

Needs YubiKey firmware 5.2 or later. The key goes in the (single) OpenPGP encryption slot.

### Build

[`wireguard-go`](https://github.com/WireGuard/wireguard-go) is a submodule, pinned at `b3bc704`. `sync-wireguard.sh` checks it out and applies `0001-external-static-dh.patch`.

```sh
./sync-wireguard.sh
CGO_ENABLED=0 go build -o yk-wireguard .
```

Linux needs `pcscd` and `libpcsclite`.

### Generate a key

```sh
yk-wireguard keygen
```

Prompts for the OpenPGP admin PIN (default `12345678`). The WireGuard public key is printed to stdout.

```sh
yk-wireguard pubkey
```

`--force` replaces the key in the slot, including a GPG encryption key.

The card does not require a tap. `up` asks for the user PIN once. The factory default is `123456`.

### Tunnel

wg-quick format, omitting `PrivateKey`:

```ini
[Interface]
Address = 10.8.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = <peer public key>
Endpoint = vpn.example:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

```sh
sudo ./yk-wireguard up --config wg0.conf
```
