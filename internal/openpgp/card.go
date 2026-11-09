package openpgp

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/natesales/yk-wireguard/internal/pcsc"
)

const (
	insVerify    = 0x20
	insDecipher  = 0x2a
	insActivate  = 0x44
	insGenerate  = 0x47
	insSelect    = 0xa4
	insGetData   = 0xca
	insPutData   = 0xda
	insVersion   = 0xf1
	pwUserDec    = 0x82
	pwAdmin      = 0x83
	doAttributes = 0xc2
	doPWStatus   = 0xc4
	doUIF        = 0xd7
	doKeyInfo    = 0xde
	doKDF        = 0xf9
)

var (
	aidOpenPGP = []byte{0xd2, 0x76, 0x00, 0x01, 0x24, 0x01}
	crtDEC     = []byte{0xb8, 0x00}
)

// Info is the OpenPGP encryption slot.
type Info struct {
	Public [32]byte
	HasKey bool
	X25519 bool
	Touch  string
}

// Card is the OpenPGP applet on a YubiKey, held open for the life of a tunnel.
// The encryption slot holds one X25519 key. PSO:DECIPHER returns the raw
// RFC 7748 shared secret. The private scalar stays on the card.
type Card struct {
	t       link
	closer  func() error
	mu      sync.Mutex
	serial  uint32
	version string

	pin      string
	prompt   func() (string, error)
	verified bool

	kdf       *kdf
	kdfLoaded bool
	maxUser   int
	maxAdmin  int
}

// FirmwareSupports reports whether firmware can generate an X25519 OpenPGP key.
// That curve arrived in the OpenPGP applet in YubiKey firmware 5.2.3.
func FirmwareSupports(v [3]byte) bool {
	if v[0] != 5 {
		return v[0] > 5
	}
	if v[1] != 2 {
		return v[1] > 2
	}
	return v[2] >= 3
}

// Open connects to the YubiKey with serial, or the only one present when serial is 0.
func Open(serial uint32) (*Card, error) {
	readers, err := pcsc.Readers()
	if err != nil {
		return nil, err
	}
	if len(readers) == 0 {
		return nil, fmt.Errorf("no smart card readers; start pcscd and plug in the yubikey")
	}
	var found []string
	var skipped []string
	var chosen *Card
	for _, reader := range readers {
		raw, err := pcsc.Connect(reader)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", reader, err))
			continue
		}
		card := &Card{t: pcscLink{card: raw}, closer: raw.Close}
		if err := card.selectApp(); err != nil {
			raw.Close()
			skipped = append(skipped, fmt.Sprintf("%s: %v", reader, err))
			continue
		}
		firm, err := card.readIdentity()
		if err != nil {
			raw.Close()
			skipped = append(skipped, fmt.Sprintf("%s: %v", reader, err))
			continue
		}
		found = append(found, fmt.Sprintf("%s serial %d firmware %s", reader, card.serial, card.version))
		if serial != 0 && card.serial != serial {
			raw.Close()
			continue
		}
		if !FirmwareSupports(firm) {
			raw.Close()
			return nil, fmt.Errorf("firmware %s cannot generate an x25519 openpgp key; 5.2.3 or later is required", card.version)
		}
		if chosen != nil {
			chosen.Close()
			raw.Close()
			return nil, fmt.Errorf("more than one yubikey is plugged in (%s); pass --serial", joinReaders(found))
		}
		chosen = card
	}
	if chosen == nil {
		if len(found) == 0 {
			if len(skipped) == 0 {
				return nil, fmt.Errorf("no yubikey with an openpgp applet")
			}
			return nil, fmt.Errorf("no yubikey with an openpgp applet (%s)", joinReaders(skipped))
		}
		return nil, fmt.Errorf("no yubikey with serial %d (found %s)", serial, joinReaders(found))
	}
	return chosen, nil
}

func joinReaders(found []string) string {
	return strings.Join(found, "; ")
}

func (c *Card) readIdentity() ([3]byte, error) {
	var firm [3]byte
	ver, err := c.t.Exchange(insVersion, 0x00, 0x00, nil)
	if err != nil {
		return firm, fmt.Errorf("version: %w", err)
	}
	firm, err = versionFromBCD(ver)
	if err != nil {
		return firm, err
	}
	c.version = fmt.Sprintf("%d.%d.%d", firm[0], firm[1], firm[2])
	aid, err := c.applicationID()
	if err != nil {
		return firm, err
	}
	serial, err := serialFromAID(aid)
	if err != nil {
		return firm, err
	}
	c.serial = serial
	return firm, nil
}

func (c *Card) applicationID() ([]byte, error) {
	body, err := c.get(0x4f)
	if err == nil && len(body) >= 14 {
		return body, nil
	}
	app, err2 := c.get(0x6e)
	if err2 != nil {
		if err != nil {
			return nil, err
		}
		return nil, err2
	}
	aid, ok := findPrimitive(app, 0x4f)
	if !ok {
		return nil, fmt.Errorf("openpgp aid is missing")
	}
	return aid, nil
}

func (c *Card) selectApp() error {
	_, err := c.t.Exchange(insSelect, 0x04, 0x00, aidOpenPGP)
	if err == nil {
		return nil
	}
	if !canActivate(err) {
		return fmt.Errorf("select openpgp: %w", err)
	}
	if _, err := c.t.Exchange(insActivate, 0x00, 0x00, nil); err != nil {
		return fmt.Errorf("activate openpgp: %w", err)
	}
	if _, err := c.t.Exchange(insSelect, 0x04, 0x00, aidOpenPGP); err != nil {
		return fmt.Errorf("select openpgp: %w", err)
	}
	return nil
}

func canActivate(err error) bool {
	var st *StatusError
	if !errors.As(err, &st) {
		return false
	}
	return st.Code() == 0x6285 || st.Code() == 0x6985
}

// Close releases the PC/SC transaction.
func (c *Card) Close() error {
	if c.closer == nil {
		return nil
	}
	err := c.closer()
	c.closer = nil
	return err
}

// Serial is the YubiKey serial number.
func (c *Card) Serial() uint32 { return c.serial }

// Version is the firmware version.
func (c *Card) Version() string { return c.version }

// Info reads the encryption slot.
func (c *Card) Info() (Info, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.info()
}

func (c *Card) info() (Info, error) {
	touch, err := c.touchName()
	if err != nil {
		return Info{}, err
	}
	body, err := c.get(doKeyInfo)
	if isNotFound(err) {
		return c.infoFromPublic(touch)
	}
	if err != nil {
		return Info{}, err
	}
	if !decPresent(body) {
		return Info{Touch: touch}, nil
	}
	attr, err := c.algorithmAttributes()
	if err != nil {
		return Info{}, err
	}
	if !isX25519(attr) {
		return Info{HasKey: true, Touch: touch}, nil
	}
	pub, err := c.public()
	if isNotFound(err) {
		return Info{Touch: touch}, nil
	}
	if errors.Is(err, errNotX25519) {
		return Info{HasKey: true, Touch: touch}, nil
	}
	if err != nil {
		return Info{}, err
	}
	return Info{Public: pub, HasKey: true, X25519: true, Touch: touch}, nil
}

func (c *Card) infoFromPublic(touch string) (Info, error) {
	pub, err := c.public()
	if err == nil {
		return Info{Public: pub, HasKey: true, X25519: true, Touch: touch}, nil
	}
	if isNotFound(err) {
		return Info{Touch: touch}, nil
	}
	if errors.Is(err, errNotX25519) {
		return Info{HasKey: true, Touch: touch}, nil
	}
	return Info{}, err
}

// algorithmAttributes reads the encryption key's algorithm from the
// application related data. Firmware 5.4 rejects GET DATA of tag C2 itself.
func (c *Card) algorithmAttributes() ([]byte, error) {
	body, err := c.get(0x6e)
	if err != nil {
		return nil, err
	}
	attr, ok := findPrimitive(body, doAttributes)
	if !ok {
		return nil, fmt.Errorf("openpgp encryption attributes are missing")
	}
	return attr, nil
}

func decPresent(info []byte) bool {
	for i := 0; i+1 < len(info); i += 2 {
		if info[i] == 0x02 && info[i+1] != 0 {
			return true
		}
	}
	return false
}

var errNotX25519 = errors.New("not an x25519 public key")

func (c *Card) public() ([32]byte, error) {
	body, err := c.t.Exchange(insGenerate, 0x81, 0x00, crtDEC)
	if err != nil {
		return [32]byte{}, err
	}
	pub, err := parsePublic(body)
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: %s", errNotX25519, err.Error())
	}
	return pub, nil
}

func (c *Card) touchName() (string, error) {
	raw, present, err := c.readUIF()
	if err != nil || !present {
		return "never", err
	}
	return touchBehavior(raw), nil
}

func (c *Card) readUIF() (byte, bool, error) {
	body, err := c.get(doUIF)
	if isNotFound(err) || (err == nil && len(body) == 0) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return body[0], true, nil
}

func touchBehavior(u byte) string {
	switch u {
	case 0x00:
		return "never"
	case 0x01, 0x02:
		return "always"
	case 0x03, 0x04:
		return "cached"
	default:
		return fmt.Sprintf("0x%02x", u)
	}
}

func uifFixed(u byte) bool { return u == 0x02 || u == 0x04 }

// Generate creates an X25519 key in the encryption slot and turns touch off.
// The user PIN is checked once, when the tunnel starts, and the open session
// covers later handshakes.
func (c *Card) Generate(adminPIN string) ([32]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	current, present, err := c.readUIF()
	if err != nil {
		return [32]byte{}, err
	}
	if present && uifFixed(current) && touchBehavior(current) != "never" {
		return [32]byte{}, fmt.Errorf("openpgp touch policy is fixed at %s", touchBehavior(current))
	}
	if err := c.verify(pwAdmin, adminPIN, "admin"); err != nil {
		return [32]byte{}, err
	}
	if err := c.put(doAttributes, x25519Attributes()); err != nil {
		return [32]byte{}, fmt.Errorf("set x25519: %w", err)
	}
	body, err := c.t.Exchange(insGenerate, 0x80, 0x00, crtDEC)
	if err != nil {
		return [32]byte{}, fmt.Errorf("generate x25519: %w", err)
	}
	pub, err := parsePublic(body)
	if err != nil {
		return [32]byte{}, err
	}
	if !present || !uifFixed(current) {
		if err := c.put(doUIF, []byte{0x00, 0x20}); err != nil {
			return [32]byte{}, fmt.Errorf("set touch policy: %w", err)
		}
	}
	return pub, nil
}

// UsePIN supplies the user PIN checked once when the tunnel starts.
func (c *Card) UsePIN(pin string, prompt func() (string, error)) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pin = pin
	c.prompt = prompt
	c.verified = false
	return nil
}

// Unlock verifies the user PIN before the tunnel starts.
func (c *Card) Unlock() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.verified {
		return nil
	}
	return c.verifyUser()
}

// SharedSecret performs X25519 with the encryption key and peerPublic.
func (c *Card) SharedSecret(peer []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(peer) != 32 {
		return nil, fmt.Errorf("peer public key is %d bytes", len(peer))
	}
	if !c.verified {
		if err := c.verifyUser(); err != nil {
			return nil, err
		}
	}
	secret, err := c.decipher(peer)
	if err == nil || !isDenied(err) {
		return secret, err
	}
	c.verified = false
	if err := c.verifyUser(); err != nil {
		return nil, err
	}
	return c.decipher(peer)
}

func (c *Card) decipher(peer []byte) ([]byte, error) {
	body, err := c.t.Exchange(insDecipher, 0x80, 0x86, cipherData(peer))
	if err != nil {
		return nil, fmt.Errorf("x25519: %w", err)
	}
	if len(body) != 32 {
		return nil, fmt.Errorf("x25519 shared secret is %d bytes", len(body))
	}
	if allZero(body) {
		return nil, fmt.Errorf("x25519 shared secret is zero")
	}
	return append([]byte(nil), body...), nil
}

func (c *Card) verifyUser() error {
	pin := c.pin
	if pin == "" {
		if c.prompt == nil {
			return fmt.Errorf("openpgp encryption slot requires the user pin")
		}
		got, err := c.prompt()
		if err != nil {
			return err
		}
		pin = got
	}
	if err := c.verify(pwUserDec, pin, "user"); err != nil {
		return err
	}
	c.verified = true
	if c.pin == "" {
		c.pin = pin
	}
	return nil
}

func (c *Card) verify(p2 byte, pin, which string) error {
	payload, err := c.preparePIN(p2, pin)
	if err != nil {
		return err
	}
	_, err = c.t.Exchange(insVerify, 0x00, p2, payload)
	if err == nil {
		return nil
	}
	var auth *AuthError
	if errors.As(err, &auth) {
		return fmt.Errorf("openpgp %s pin rejected, %d tries left", which, auth.Retries)
	}
	var st *StatusError
	if errors.As(err, &st) && (st.Code() == 0x6982 || st.Code() == 0x6983) {
		left := c.attempts(p2)
		if st.Code() == 0x6983 {
			left = 0
		}
		return fmt.Errorf("openpgp %s pin rejected, %d tries left", which, left)
	}
	return fmt.Errorf("verify openpgp %s pin: %w", which, err)
}

func (c *Card) preparePIN(p2 byte, pin string) ([]byte, error) {
	if pin == "" {
		return nil, fmt.Errorf("empty pin")
	}
	if err := c.loadKDF(); err != nil {
		return nil, err
	}
	min, max := 6, c.maxUser
	which := "user"
	var salt []byte
	if p2 == pwAdmin {
		min, max = 8, c.maxAdmin
		which = "admin"
		if c.kdf != nil {
			salt = c.kdf.admin
		}
	}
	if max == 0 {
		max = 127
	}
	var out []byte
	var err error
	if c.kdf == nil {
		out = []byte(pin)
	} else {
		out, err = c.kdf.process(salt, pin)
		if err != nil {
			return nil, err
		}
	}
	if len(out) < min || len(out) > max {
		return nil, fmt.Errorf("openpgp %s pin must be %d to %d characters", which, min, max)
	}
	return out, nil
}

func (c *Card) loadKDF() error {
	if c.kdfLoaded {
		return nil
	}
	status, err := c.get(doPWStatus)
	if err != nil {
		return fmt.Errorf("pin status: %w", err)
	}
	if len(status) < 7 {
		return fmt.Errorf("pin status is %d bytes", len(status))
	}
	c.maxUser = int(status[1])
	c.maxAdmin = int(status[3])
	body, err := c.get(doKDF)
	if isNotFound(err) {
		c.kdfLoaded = true
		return nil
	}
	if err != nil {
		return fmt.Errorf("kdf: %w", err)
	}
	c.kdf, err = parseKDF(body)
	if err != nil {
		return err
	}
	c.kdfLoaded = true
	return nil
}

func (c *Card) attempts(p2 byte) int {
	status, err := c.get(doPWStatus)
	if err != nil || len(status) < 7 {
		return 0
	}
	if p2 == pwAdmin {
		return int(status[6])
	}
	return int(status[4])
}

func (c *Card) get(tag byte) ([]byte, error) {
	return c.t.Exchange(insGetData, 0x00, tag, nil)
}

func (c *Card) put(tag byte, data []byte) error {
	_, err := c.t.Exchange(insPutData, 0x00, tag, data)
	return err
}

func isNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

func isDenied(err error) bool {
	var st *StatusError
	return errors.As(err, &st) && st.Code() == 0x6982
}
