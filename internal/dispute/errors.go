package dispute

import (
	"github.com/pkg/errors"
)

var (
	ErrInvalidVerdicts = errors.New("invalid verdicts")
	ErrInvalidCulprits = errors.New("invalid culprits")
	ErrInvalidFaults   = errors.New("invalid faults")
)
