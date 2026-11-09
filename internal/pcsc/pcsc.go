//go:build linux || darwin

package pcsc

import (
	"fmt"
	"sync"

	"github.com/ElMostafaIdrassi/goscard"
)

// Card is an exclusive PC/SC transaction held open for the life of a tunnel.
// libpcsclite is loaded with purego, so this package builds with CGO_ENABLED=0.
type Card struct {
	ctx    goscard.Context
	card   goscard.Card
	pci    goscard.SCardIORequest
	Reader string
}

var (
	initOnce sync.Once
	initErr  error
)

func ensure() error {
	initOnce.Do(func() {
		err := goscard.Initialize(goscard.NewDefaultLogger(goscard.LogLevelNone))
		if err != nil {
			initErr = fmt.Errorf("load libpcsclite: %w", err)
		}
	})
	return initErr
}

// Readers lists PC/SC readers. An empty list means pcscd is up and no card is present.
func Readers() ([]string, error) {
	if err := ensure(); err != nil {
		return nil, err
	}
	ctx, _, err := goscard.NewContext(goscard.SCardScopeSystem, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("pcsc context: %w", err)
	}
	defer ctx.Release()
	readers, _, err := ctx.ListReaders(nil)
	if err != nil {
		return nil, fmt.Errorf("list readers: %w", err)
	}
	return readers, nil
}

// Connect opens reader and holds a transaction until Close.
func Connect(reader string) (*Card, error) {
	if err := ensure(); err != nil {
		return nil, err
	}
	ctx, _, err := goscard.NewContext(goscard.SCardScopeSystem, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("pcsc context: %w", err)
	}
	card, _, err := ctx.Connect(reader, goscard.SCardShareExclusive, goscard.SCardProtocolT0|goscard.SCardProtocolT1)
	if err != nil {
		ctx.Release()
		return nil, fmt.Errorf("connect %s: %w", reader, err)
	}
	if _, err := card.BeginTransaction(); err != nil {
		card.Disconnect(goscard.SCardLeaveCard)
		ctx.Release()
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	pci := goscard.SCardIoRequestT1
	if card.ActiveProtocol() == goscard.SCardProtocolT0 {
		pci = goscard.SCardIoRequestT0
	}
	return &Card{ctx: ctx, card: card, pci: pci, Reader: reader}, nil
}

// Transmit sends one APDU and returns the raw response, including the status word.
func (c *Card) Transmit(apdu []byte) ([]byte, error) {
	resp, _, err := c.card.Transmit(&c.pci, apdu, nil)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Close ends the transaction and releases the context.
func (c *Card) Close() error {
	_, _ = c.card.EndTransaction(goscard.SCardLeaveCard)
	_, _ = c.card.Disconnect(goscard.SCardLeaveCard)
	_, err := c.ctx.Release()
	if err != nil {
		return fmt.Errorf("release pcsc context: %w", err)
	}
	return nil
}
