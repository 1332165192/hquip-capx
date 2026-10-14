package correlate

import "github.com/hquip/capx/internal/store"

// Engine correlates the current contents of a store on demand.
type Engine struct{ st *store.Store }

// New returns a correlation engine bound to a store.
func New(st *store.Store) *Engine { return &Engine{st: st} }

// Groups builds correlated session timelines from the store's current state.
func (e *Engine) Groups() []*Group {
	return Build(Input{
		Flows:   e.st.ListFlows(),
		HTTP:    e.st.ListHTTPTx(""),
		WS:      e.st.ListWS(),
		Hooks:   e.st.ListHookEvents(),
		MemHits: e.st.ListMemHits(),
	})
}
