package notifications

import (
	"context"
	"sync"
)

// Fake has no transport or credentials. It is available for foundation tests,
// including independently configured fake Gmail and fake SES connectors.
type Fake struct {
	mu       sync.Mutex
	provider string
	result   Result
	calls    int
}

func NewFake(provider string, result Result) *Fake { return &Fake{provider: provider, result: result} }
func (f *Fake) Provider() string                   { return f.provider }
func (f *Fake) Send(_ context.Context, _ Message) Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.result
}
func (f *Fake) Calls() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }
