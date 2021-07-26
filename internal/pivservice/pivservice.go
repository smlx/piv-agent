package pivservice

import (
	"sync"

	"go.uber.org/zap"
)

// PIVService represents a collection of tokens and slots accessed by the
// Personal Identity Verifaction card interface.
type PIVService struct {
	mu           sync.Mutex
	log          *zap.Logger
	securityKeys []SecurityKey
}

// New constructs a PIV and returns it.
func New(l *zap.Logger) *PIVService {
	return &PIVService{
		log: l,
	}
}
