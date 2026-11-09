//go:build !linux && !darwin

package pcsc

import "fmt"

// Card is an exclusive PC/SC transaction. This platform has no pure-Go PC/SC binding.
type Card struct {
	Reader string
}

// Readers reports that PC/SC is unavailable.
func Readers() ([]string, error) {
	return nil, unsupported()
}

// Connect reports that PC/SC is unavailable.
func Connect(reader string) (*Card, error) {
	return nil, unsupported()
}

// Transmit reports that PC/SC is unavailable.
func (c *Card) Transmit(apdu []byte) ([]byte, error) {
	return nil, unsupported()
}

// Close reports that PC/SC is unavailable.
func (c *Card) Close() error {
	return unsupported()
}

func unsupported() error {
	return fmt.Errorf("pcsc is implemented for linux and darwin")
}
