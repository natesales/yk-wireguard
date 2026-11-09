package openpgp

import (
	"bytes"
	"testing"
)

type fake struct {
	fn func(ins, p1, p2 byte, data []byte) ([]byte, error)
}

func (f fake) Exchange(ins, p1, p2 byte, data []byte) ([]byte, error) {
	return f.fn(ins, p1, p2, data)
}
func (fake) Close() error { return nil }

func notFound() error { return &StatusError{SW1: 0x6a, SW2: 0x88} }

func pwStatus() []byte { return []byte{0x01, 127, 127, 127, 3, 3, 3} }

func TestAttributesNestedInApplicationData(t *testing.T) {
	// Firmware 5.4 returns algorithm attributes inside the 6E template, with a
	// long-form length, and rejects a direct GET DATA of tag C2.
	inner := []byte{0xc2, 0x06, 0x01, 0x08, 0x00, 0x00, 0x11, 0x00, 0xc4, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	disc := append([]byte{0x73, 0x82, 0x00, byte(len(inner))}, inner...)
	body := append([]byte{0x6e, 0x82, 0x00, byte(len(disc))}, disc...)
	got, ok := findPrimitive(body, 0xc2)
	if !ok || !bytes.Equal(got, []byte{0x01, 0x08, 0x00, 0x00, 0x11, 0x00}) {
		t.Fatalf("attr %x ok %v", got, ok)
	}
	if isX25519(got) {
		t.Fatal("rsa attributes looked like x25519")
	}
	if !isX25519(x25519Attributes()) {
		t.Fatal("x25519 attributes were not recognized")
	}
}

func TestFirmwareSupports(t *testing.T) {
	if !FirmwareSupports([3]byte{5, 2, 3}) || !FirmwareSupports([3]byte{5, 4, 2}) || !FirmwareSupports([3]byte{5, 7, 0}) {
		t.Fatal("expected support")
	}
	if FirmwareSupports([3]byte{5, 2, 2}) || FirmwareSupports([3]byte{4, 4, 0}) {
		t.Fatal("expected no support")
	}
}

func TestParsePublicAndCipher(t *testing.T) {
	pub := bytes.Repeat([]byte{0x3c}, 32)
	body := append([]byte{0x7f, 0x49, 0x22, 0x86, 0x20}, pub...)
	got, err := parsePublic(body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:], pub) {
		t.Fatalf("public %x", got)
	}
	prefixed := append([]byte{0x7f, 0x49, 0x23, 0x86, 0x21, 0x40}, pub...)
	got, err = parsePublic(prefixed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:], pub) {
		t.Fatalf("prefixed %x", got)
	}
	peer := bytes.Repeat([]byte{0x11}, 32)
	data := cipherData(peer)
	if len(data) != 39 || data[0] != 0xa6 || data[1] != 0x25 || !bytes.Equal(data[len(data)-32:], peer) {
		t.Fatalf("cipher %x", data)
	}
}

func TestKDFVector(t *testing.T) {
	body := []byte{
		0x81, 0x01, 0x03,
		0x82, 0x01, 0x08,
		0x83, 0x04, 0x00, 0x00, 0x00, 48,
		0x84, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	}
	k, err := parseKDF(body)
	if err != nil {
		t.Fatal(err)
	}
	got, err := k.process(nil, "12345678")
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x71, 0x53, 0x31, 0x51, 0x4f, 0x93, 0x88, 0x22,
		0xc4, 0xad, 0x45, 0xee, 0xd5, 0xb2, 0xe7, 0xfd,
		0xd3, 0xaa, 0x94, 0x57, 0x42, 0x06, 0x48, 0x85,
		0xc9, 0x35, 0x0d, 0x64, 0x91, 0x86, 0xad, 0x15,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("kdf %x", got)
	}
	none, err := parseKDF([]byte{0x81, 0x01, 0x00})
	if err != nil || none != nil {
		t.Fatalf("none %#v %v", none, err)
	}
}

func TestGenerateSendsX25519(t *testing.T) {
	pub := bytes.Repeat([]byte{0x3c}, 32)
	var sawVerify, sawAttr, sawGen, sawUIF bool
	c := &Card{t: fake{fn: func(ins, p1, p2 byte, data []byte) ([]byte, error) {
		switch ins {
		case insSelect:
			if !bytes.Equal(data, aidOpenPGP) {
				t.Fatalf("aid %x", data)
			}
			return nil, nil
		case insGetData:
			switch p2 {
			case doUIF, doKDF:
				return nil, notFound()
			case doPWStatus:
				return pwStatus(), nil
			default:
				t.Fatalf("get %02x", p2)
			}
		case insVerify:
			sawVerify = true
			if p2 != pwAdmin || string(data) != "12345678" {
				t.Fatalf("verify p2 %02x data %q", p2, data)
			}
			return nil, nil
		case insPutData:
			switch p2 {
			case doAttributes:
				sawAttr = true
				if !bytes.Equal(data, x25519Attributes()) {
					t.Fatalf("attributes %x", data)
				}
			case doUIF:
				sawUIF = true
				if !bytes.Equal(data, []byte{0x00, 0x20}) {
					t.Fatalf("uif %x", data)
				}
			default:
				t.Fatalf("put %02x", p2)
			}
			return nil, nil
		case insGenerate:
			sawGen = true
			if p1 != 0x80 || !bytes.Equal(data, crtDEC) {
				t.Fatalf("generate p1 %02x data %x", p1, data)
			}
			return append([]byte{0x7f, 0x49, 0x22, 0x86, 0x20}, pub...), nil
		default:
			t.Fatalf("ins %02x", ins)
		}
		return nil, nil
	}}}
	got, err := c.Generate("12345678")
	if err != nil {
		t.Fatal(err)
	}
	if !sawVerify || !sawAttr || !sawGen || !sawUIF {
		t.Fatalf("verify %v attr %v gen %v uif %v", sawVerify, sawAttr, sawGen, sawUIF)
	}
	if !bytes.Equal(got[:], pub) {
		t.Fatalf("public %x", got)
	}
}

func TestGenerateRejectsShortAdminPIN(t *testing.T) {
	c := &Card{t: fake{fn: func(ins, p1, p2 byte, data []byte) ([]byte, error) {
		if ins == insVerify {
			t.Fatal("verify was sent")
		}
		if ins == insGetData && (p2 == doUIF || p2 == doKDF) {
			return nil, notFound()
		}
		if ins == insGetData && p2 == doPWStatus {
			return pwStatus(), nil
		}
		t.Fatalf("unexpected ins %02x p2 %02x", ins, p2)
		return nil, nil
	}}}
	_, err := c.Generate("short")
	if err == nil {
		t.Fatal("expected a length error")
	}
}

func TestSharedSecretVerifiesOnce(t *testing.T) {
	peer := bytes.Repeat([]byte{0x55}, 32)
	secret := bytes.Repeat([]byte{0x66}, 32)
	verifies := 0
	c := &Card{t: fake{fn: func(ins, p1, p2 byte, data []byte) ([]byte, error) {
		switch ins {
		case insGetData:
			if p2 == doKDF {
				return nil, notFound()
			}
			if p2 == doPWStatus {
				return pwStatus(), nil
			}
			t.Fatalf("get %02x", p2)
		case insVerify:
			verifies++
			if p2 != pwUserDec || string(data) != "123456" {
				t.Fatalf("verify %02x %q", p2, data)
			}
			return nil, nil
		case insDecipher:
			if !bytes.Equal(data, cipherData(peer)) {
				t.Fatalf("decipher %x", data)
			}
			return secret, nil
		default:
			t.Fatalf("ins %02x", ins)
		}
		return nil, nil
	}}}
	if err := c.UsePIN("123456", nil); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		got, err := c.SharedSecret(peer)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, secret) {
			t.Fatalf("secret %x", got)
		}
	}
	if verifies != 1 {
		t.Fatalf("verifies %d", verifies)
	}
}

func TestSharedSecretRejectsZero(t *testing.T) {
	c := &Card{t: fake{fn: func(ins, p1, p2 byte, data []byte) ([]byte, error) {
		switch ins {
		case insGetData:
			if p2 == doKDF {
				return nil, notFound()
			}
			return pwStatus(), nil
		case insVerify:
			return nil, nil
		case insDecipher:
			return bytes.Repeat([]byte{0}, 32), nil
		default:
			t.Fatalf("ins %02x", ins)
		}
		return nil, nil
	}}, pin: "123456"}
	_, err := c.SharedSecret(bytes.Repeat([]byte{0x01}, 32))
	if err == nil || err.Error() != "x25519 shared secret is zero" {
		t.Fatal(err)
	}
}

func TestInfoX25519AndEmpty(t *testing.T) {
	pub := bytes.Repeat([]byte{0xab}, 32)
	present := true
	c := &Card{t: fake{fn: func(ins, p1, p2 byte, data []byte) ([]byte, error) {
		if ins != insGetData && ins != insGenerate {
			t.Fatalf("ins %02x", ins)
		}
		if ins == insGenerate {
			return append([]byte{0x7f, 0x49, 0x22, 0x86, 0x20}, pub...), nil
		}
		switch p2 {
		case doUIF:
			return []byte{0x03, 0x20}, nil
		case doKeyInfo:
			if present {
				return []byte{0x01, 0x00, 0x02, 0x01, 0x03, 0x00}, nil
			}
			return []byte{0x02, 0x00}, nil
		case 0x6e:
			attr := x25519Attributes()
			inner := append([]byte{0xc2, byte(len(attr))}, attr...)
			disc := append([]byte{0x73, byte(len(inner))}, inner...)
			return append([]byte{0x6e, byte(len(disc))}, disc...), nil
		default:
			t.Fatalf("get %02x", p2)
		}
		return nil, nil
	}}}
	info, err := c.Info()
	if err != nil {
		t.Fatal(err)
	}
	if !info.X25519 || info.Touch != "cached" || !bytes.Equal(info.Public[:], pub) {
		t.Fatalf("%+v", info)
	}
	present = false
	info, err = c.Info()
	if err != nil {
		t.Fatal(err)
	}
	if info.HasKey || info.X25519 {
		t.Fatalf("empty %+v", info)
	}
}

func TestActivateThenSelect(t *testing.T) {
	selects := 0
	c := &Card{t: fake{fn: func(ins, p1, p2 byte, data []byte) ([]byte, error) {
		switch ins {
		case insSelect:
			selects++
			if selects == 1 {
				return nil, &StatusError{SW1: 0x69, SW2: 0x85}
			}
			return nil, nil
		case insActivate:
			return nil, nil
		default:
			t.Fatalf("ins %02x", ins)
		}
		return nil, nil
	}}}
	err := c.selectApp()
	if err != nil {
		t.Fatal(err)
	}
	if selects != 2 {
		t.Fatalf("selects %d", selects)
	}
}

func TestPinRejected(t *testing.T) {
	c := &Card{t: fake{fn: func(ins, p1, p2 byte, data []byte) ([]byte, error) {
		switch ins {
		case insGetData:
			if p2 == doUIF || p2 == doKDF {
				return nil, notFound()
			}
			return pwStatus(), nil
		case insVerify:
			return nil, &AuthError{Retries: 2}
		default:
			t.Fatalf("ins %02x", ins)
		}
		return nil, nil
	}}}
	_, err := c.Generate("12345678")
	if err == nil || err.Error() != "openpgp admin pin rejected, 2 tries left" {
		t.Fatal(err)
	}
}

func TestSerialAndFirmware(t *testing.T) {
	aid := []byte{0xd2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0x00, 0x06, 0x20, 0x71, 0x00, 0x91, 0x00, 0x00}
	n, err := serialFromAID(aid)
	if err != nil || n != 20710091 {
		t.Fatalf("serial %d %v", n, err)
	}
	v, err := versionFromBCD([]byte{0x05, 0x04, 0x03})
	if err != nil || v != [3]byte{5, 4, 3} {
		t.Fatalf("version %v %v", v, err)
	}
	if !FirmwareSupports([3]byte{5, 2, 3}) || !FirmwareSupports(v) {
		t.Fatal("5.2.3 and later should be supported")
	}
	if FirmwareSupports([3]byte{5, 2, 2}) {
		t.Fatal("5.2.2 should be rejected")
	}
}
