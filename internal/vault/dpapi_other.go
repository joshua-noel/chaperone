//go:build !windows

package vault

type dpapiUnsupported struct{}

func newDPAPIUser([]byte) KeyWrapper { return dpapiUnsupported{} }

func (dpapiUnsupported) Name() string                  { return DPAPIName }
func (dpapiUnsupported) Wrap([]byte) ([]byte, error)   { return nil, ErrUnsupported }
func (dpapiUnsupported) Unwrap([]byte) ([]byte, error) { return nil, ErrUnsupported }
