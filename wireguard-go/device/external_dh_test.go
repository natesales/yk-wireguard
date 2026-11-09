/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

func TestExternalStaticDHHandshake(t *testing.T) {
	sk1, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	sk2, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	tun1 := tuntest.NewChannelTUN()
	tun2 := tuntest.NewChannelTUN()
	logger := NewLogger(LogLevelError, "")
	dev1 := NewDevice(tun1.TUN(), conn.NewDefaultBind(), logger)
	dev2 := NewDevice(tun2.TUN(), conn.NewDefaultBind(), logger)
	defer dev1.Close()
	defer dev2.Close()

	dev1.SetPrivateKey(sk1)
	err = dev2.SetExternalStaticKey(sk2.publicKey(), func(peer NoisePublicKey) ([NoisePublicKeySize]byte, error) {
		return sk2.sharedSecret(peer)
	})
	if err != nil {
		t.Fatal(err)
	}

	peer1, err := dev2.NewPeer(sk1.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	peer2, err := dev1.NewPeer(sk2.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	peer1.Start()
	peer2.Start()

	if !bytes.Equal(peer1.handshake.precomputedStaticStatic[:], peer2.handshake.precomputedStaticStatic[:]) {
		t.Fatal("static-static shared secrets differ")
	}

	msg1, err := dev1.CreateMessageInitiation(peer2)
	if err != nil {
		t.Fatal(err)
	}
	if got := dev2.ConsumeMessageInitiation(msg1); got == nil {
		t.Fatal("responder rejected initiation")
	}
	msg2, err := dev2.CreateMessageResponse(peer1)
	if err != nil {
		t.Fatal(err)
	}
	if got := dev1.ConsumeMessageResponse(msg2); got == nil {
		t.Fatal("initiator rejected response")
	}

	out, err := dev2.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(out), []byte("private_key=")) {
		t.Fatalf("external identity leaked a private key:\n%s", out)
	}
}
