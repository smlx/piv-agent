// package pivagent wraps the low-level token hardware access logic in higher
// level abstraction. It take care of reloading security keys which are plugged
// and unplugged.
package pivagent

import (
	"sync"

	"go.uber.org/zap"
)

// PIVAgent represents a collection of tokens and slots accessed by the Personal
// Identity Verifaction card interface.
type PIVAgent struct {
	mutex sync.Mutex
	log   *zap.Logger
}

// New constructs a PIV and returns it.
func New(l *zap.Logger) *PIVAgent {
	return &PIVAgent{
		log: l,
	}
}
