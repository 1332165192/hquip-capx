//go:build !windivert && !nfqueue

package inline

import (
	"context"

	"github.com/hquip/capx/internal/store"
)

// stubBackend is the default no-op backend: the rule engine still works for
// validation/testing, but live packet diversion is unavailable.
type stubBackend struct{}

func newBackend() backend { return stubBackend{} }

func (stubBackend) name() string    { return "stub" }
func (stubBackend) available() bool { return false }
func (stubBackend) run(context.Context, string, *Engine, *store.Store) error {
	return ErrNoBackend
}
func (stubBackend) send([]byte, bool) error { return ErrNoBackend }
func (stubBackend) runRedirect(context.Context, string, *Redirector, *store.Store) error {
	return ErrNoBackend
}
