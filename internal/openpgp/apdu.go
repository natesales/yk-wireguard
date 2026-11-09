package openpgp

import (
	"fmt"
	"strconv"

	"github.com/natesales/yk-wireguard/internal/pcsc"
)

const insGetResponse = 0xc0

// ErrNotFound is returned when a data object is absent.
var ErrNotFound = fmt.Errorf("openpgp object not found")

// StatusError is a non-success status word from the card.
type StatusError struct {
	SW1 byte
	SW2 byte
}

func (e *StatusError) Error() string {
	msg := ""
	switch e.Code() {
	case 0x6982:
		msg = "security status not satisfied"
	case 0x6983:
		msg = "authentication method blocked"
	case 0x6a80:
		msg = "incorrect parameter in command data"
	case 0x6a82, 0x6a88:
		msg = "not found"
	case 0x6a86:
		msg = "incorrect parameter"
	}
	if msg != "" {
		return fmt.Sprintf("card status %04x: %s", e.Code(), msg)
	}
	return fmt.Sprintf("card status %04x", e.Code())
}

func (e *StatusError) Code() uint16 {
	return uint16(e.SW1)<<8 | uint16(e.SW2)
}

func (e *StatusError) Unwrap() error {
	if e.Code() == 0x6a82 || e.Code() == 0x6a88 {
		return ErrNotFound
	}
	return nil
}

// AuthError is a wrong PIN, with retries remaining.
type AuthError struct {
	Retries int
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("pin rejected, %d tries left", e.Retries)
}

// link is one OpenPGP applet session.
type link interface {
	Exchange(ins, p1, p2 byte, data []byte) ([]byte, error)
	Close() error
}

type pcscLink struct {
	card *pcsc.Card
}

func (p pcscLink) Close() error { return p.card.Close() }

func (p pcscLink) Exchange(ins, p1, p2 byte, data []byte) ([]byte, error) {
	req, err := command(ins, p1, p2, data)
	if err != nil {
		return nil, err
	}
	var body []byte
	for {
		resp, err := p.card.Transmit(req)
		if err != nil {
			return nil, err
		}
		if len(resp) < 2 {
			return nil, fmt.Errorf("short card response (%d bytes)", len(resp))
		}
		sw1, sw2 := resp[len(resp)-2], resp[len(resp)-1]
		body = append(body, resp[:len(resp)-2]...)
		if sw1 == 0x61 {
			req = []byte{0x00, insGetResponse, 0x00, 0x00, 0x00}
			continue
		}
		if sw1 == 0x90 && sw2 == 0x00 {
			return body, nil
		}
		if sw1 == 0x63 && sw2&0xf0 == 0xc0 {
			return nil, &AuthError{Retries: int(sw2 & 0x0f)}
		}
		if sw1 == 0x63 && sw2 == 0x00 {
			return nil, &AuthError{Retries: 0}
		}
		return nil, &StatusError{SW1: sw1, SW2: sw2}
	}
}

func command(ins, p1, p2 byte, data []byte) ([]byte, error) {
	if len(data) > 255 {
		return nil, fmt.Errorf("apdu data is %d bytes", len(data))
	}
	out := make([]byte, 5+len(data))
	out[1] = ins
	out[2] = p1
	out[3] = p2
	out[4] = byte(len(data))
	copy(out[5:], data)
	return out, nil
}

func versionFromBCD(b []byte) ([3]byte, error) {
	var v [3]byte
	if len(b) < 3 {
		return v, fmt.Errorf("version is %d bytes", len(b))
	}
	for i := 0; i < 3; i++ {
		hi, lo := b[i]>>4, b[i]&0x0f
		if hi > 9 || lo > 9 {
			return v, fmt.Errorf("version byte %02x is not bcd", b[i])
		}
		v[i] = hi*10 + lo
	}
	return v, nil
}

func serialFromAID(aid []byte) (uint32, error) {
	if len(aid) < 14 {
		return 0, fmt.Errorf("openpgp aid is %d bytes", len(aid))
	}
	n, err := strconv.ParseUint(fmt.Sprintf("%x", aid[10:14]), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("openpgp serial: %w", err)
	}
	return uint32(n), nil
}
