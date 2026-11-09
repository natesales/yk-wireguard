package openpgp

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

// x25519OID is the OpenPGP curve OID 1.3.6.1.4.1.3029.1.5.1, without the ASN.1 tag.
var x25519OID = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x47, 0x01, 0x05, 0x01}

func x25519Attributes() []byte {
	return append([]byte{0x12}, x25519OID...)
}

func isX25519(attr []byte) bool {
	return len(attr) >= 1+len(x25519OID) && attr[0] == 0x12 && bytesEqual(attr[1:1+len(x25519OID)], x25519OID)
}

// cipherData is the PSO:DECIPHER payload for an X25519 peer public key.
// The 32 bytes are the RFC 7748 u-coordinate, the same order WireGuard uses.
func cipherData(pub []byte) []byte {
	point := append([]byte{0x86, byte(len(pub))}, pub...)
	inner := append([]byte{0x7f, 0x49, byte(len(point))}, point...)
	return append([]byte{0xa6, byte(len(inner))}, inner...)
}

func parsePublic(body []byte) ([32]byte, error) {
	var out [32]byte
	point, ok := findPrimitive(body, 0x86)
	if !ok {
		point = body
	}
	if len(point) == 33 && point[0] == 0x40 {
		point = point[1:]
	}
	if len(point) != 32 {
		return out, fmt.Errorf("x25519 public key is %d bytes", len(point))
	}
	copy(out[:], point)
	return out, nil
}

type kdf struct {
	hashID byte
	iter   int
	user   []byte
	admin  []byte
}

func parseKDF(body []byte) (*kdf, error) {
	if len(body) == 0 {
		return nil, nil
	}
	fields, err := tlvMap(body)
	if err != nil {
		return nil, err
	}
	alg := fields[0x81]
	if len(alg) == 0 || alg[0] == 0 {
		return nil, nil
	}
	if len(alg) != 1 || alg[0] != 3 {
		return nil, fmt.Errorf("openpgp kdf algorithm %x", alg)
	}
	hashID := fields[0x82]
	if len(hashID) != 1 {
		return nil, fmt.Errorf("openpgp kdf hash is missing")
	}
	iter := 0
	for _, b := range fields[0x83] {
		iter = iter<<8 | int(b)
	}
	if len(fields[0x84]) == 0 {
		return nil, fmt.Errorf("openpgp kdf is missing the user salt")
	}
	return &kdf{
		hashID: hashID[0],
		iter:   iter,
		user:   append([]byte(nil), fields[0x84]...),
		admin:  append([]byte(nil), fields[0x86]...),
	}, nil
}

func (k *kdf) process(salt []byte, pin string) ([]byte, error) {
	if len(salt) == 0 {
		salt = k.user
	}
	data := append(append([]byte{}, salt...), pin...)
	if len(data) == 0 || k.iter < 0 || k.iter > 64<<20 {
		return nil, fmt.Errorf("openpgp kdf iteration count %d", k.iter)
	}
	h, err := kdfHash(k.hashID)
	if err != nil {
		return nil, err
	}
	n, rem := k.iter/len(data), k.iter%len(data)
	for i := 0; i < n; i++ {
		h.Write(data)
	}
	h.Write(data[:rem])
	return h.Sum(nil), nil
}

func kdfHash(id byte) (hash.Hash, error) {
	switch id {
	case 0x08:
		return sha256.New(), nil
	case 0x0a:
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("openpgp kdf hash %02x", id)
	}
}

func tlvMap(b []byte) (map[byte][]byte, error) {
	out := map[byte][]byte{}
	for len(b) > 0 {
		tag, val, rest, _, err := nextTLV(b)
		if err != nil {
			return nil, err
		}
		if len(tag) == 1 {
			out[tag[0]] = val
		}
		b = rest
	}
	return out, nil
}

func findPrimitive(b []byte, want byte) ([]byte, bool) {
	for len(b) > 0 {
		tag, val, rest, constructed, err := nextTLV(b)
		if err != nil {
			return nil, false
		}
		if !constructed && len(tag) == 1 && tag[0] == want {
			return val, true
		}
		if constructed {
			if found, ok := findPrimitive(val, want); ok {
				return found, true
			}
		}
		b = rest
	}
	return nil, false
}

func nextTLV(b []byte) (tag, val, rest []byte, constructed bool, err error) {
	if len(b) == 0 {
		return nil, nil, nil, false, fmt.Errorf("truncated tlv")
	}
	constructed = b[0]&0x20 != 0
	tagLen := 1
	if b[0]&0x1f == 0x1f {
		for {
			if tagLen >= len(b) {
				return nil, nil, nil, false, fmt.Errorf("truncated tag")
			}
			more := b[tagLen]&0x80 != 0
			tagLen++
			if !more {
				break
			}
		}
	}
	if tagLen >= len(b) {
		return nil, nil, nil, false, fmt.Errorf("truncated tlv")
	}
	n, lenLen, err := tlvLength(b[tagLen:])
	if err != nil {
		return nil, nil, nil, false, err
	}
	start := tagLen + lenLen
	if n > len(b)-start {
		return nil, nil, nil, false, fmt.Errorf("tlv length %d exceeds %d", n, len(b)-start)
	}
	return b[:tagLen], b[start : start+n], b[start+n:], constructed, nil
}

func tlvLength(b []byte) (int, int, error) {
	if len(b) == 0 {
		return 0, 0, fmt.Errorf("truncated length")
	}
	if b[0] < 0x80 {
		return int(b[0]), 1, nil
	}
	n := int(b[0] & 0x7f)
	if n == 0 || n > 3 || len(b) < 1+n {
		return 0, 0, fmt.Errorf("bad tlv length")
	}
	v := 0
	for i := 0; i < n; i++ {
		v = v<<8 | int(b[1+i])
	}
	return v, 1 + n, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	diff := byte(0)
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func allZero(b []byte) bool {
	z := byte(0)
	for _, c := range b {
		z |= c
	}
	return z == 0
}
