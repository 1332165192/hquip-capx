//go:build !windows

package wxdesk

type nativeBackend struct{}

func prepareNative(PrepareOptions) (Package, error) { return Package{}, ErrUnsupported }
func startNativeEnvironment() error                 { return ErrUnsupported }

func newBackend() Backend              { return &nativeBackend{} }
func (*nativeBackend) Available() bool { return false }
func (*nativeBackend) Environment() Environment {
	return Environment{Mode: "unsupported", Note: ErrUnsupported.Error()}
}
func (*nativeBackend) Windows() ([]Window, error)           { return nil, ErrUnsupported }
func (*nativeBackend) Launch() error                        { return ErrUnsupported }
func (*nativeBackend) Show(string) error                    { return ErrUnsupported }
func (*nativeBackend) Screenshot(string) ([]byte, error)    { return nil, ErrUnsupported }
func (*nativeBackend) Tap(string, int, int, int, int) error { return ErrUnsupported }
func (*nativeBackend) Input(string, string) error           { return ErrUnsupported }
func (*nativeBackend) Key(string, string) error             { return ErrUnsupported }
func (*nativeBackend) Scroll(string, int) error             { return ErrUnsupported }
