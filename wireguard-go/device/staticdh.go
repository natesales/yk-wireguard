/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import "errors"

// StaticDHFunc computes X25519(staticPrivate, peerPublic) for the device
// identity. The static private key never enters this process.
type StaticDHFunc func(peerPublic NoisePublicKey) ([NoisePublicKeySize]byte, error)

// SetExternalStaticKey installs a long-term public key whose matching private
// key lives outside the process. dh is called for every static Diffie-Hellman,
// including the static-static value cached when a peer is added.
func (device *Device) SetExternalStaticKey(publicKey NoisePublicKey, dh StaticDHFunc) error {
	if dh == nil {
		return errors.New("external static key requires a DH function")
	}
	if publicKey.IsZero() {
		return errors.New("external static key requires a public key")
	}

	device.staticIdentity.Lock()
	defer device.staticIdentity.Unlock()

	device.peers.Lock()
	defer device.peers.Unlock()

	lockedPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		peer.handshake.mutex.RLock()
		lockedPeers = append(lockedPeers, peer)
	}
	unlock := true
	defer func() {
		if unlock {
			for _, peer := range lockedPeers {
				peer.handshake.mutex.RUnlock()
			}
		}
	}()

	for key, peer := range device.peers.keyMap {
		if peer.handshake.remoteStatic.Equals(publicKey) {
			peer.handshake.mutex.RUnlock()
			removePeerLocked(device, peer, key)
			peer.handshake.mutex.RLock()
		}
	}

	type computed struct {
		peer *Peer
		ss   [NoisePublicKeySize]byte
	}
	fresh := make([]computed, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		ss, err := dh(peer.handshake.remoteStatic)
		if err != nil {
			return err
		}
		if isZero(ss[:]) {
			return errInvalidPublicKey
		}
		fresh = append(fresh, computed{peer, ss})
	}

	device.staticIdentity.privateKey = NoisePrivateKey{}
	device.staticIdentity.publicKey = publicKey
	device.staticIdentity.dh = dh
	device.cookieChecker.Init(publicKey)

	expiredPeers := make([]*Peer, 0, len(fresh))
	for _, item := range fresh {
		item.peer.handshake.precomputedStaticStatic = item.ss
		expiredPeers = append(expiredPeers, item.peer)
	}

	unlock = false
	for _, peer := range lockedPeers {
		peer.handshake.mutex.RUnlock()
	}
	for _, peer := range expiredPeers {
		peer.ExpireCurrentKeypairs()
	}
	return nil
}

// staticSharedSecret uses the external DH function when one is installed.
// The caller holds staticIdentity's lock.
func (device *Device) staticSharedSecret(pk NoisePublicKey) ([NoisePublicKeySize]byte, error) {
	if device.staticIdentity.dh != nil {
		ss, err := device.staticIdentity.dh(pk)
		if err != nil {
			var zero [NoisePublicKeySize]byte
			return zero, err
		}
		if isZero(ss[:]) {
			return ss, errInvalidPublicKey
		}
		return ss, nil
	}
	return device.staticIdentity.privateKey.sharedSecret(pk)
}
