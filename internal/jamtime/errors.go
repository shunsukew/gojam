package jamtime

import (
	"github.com/pkg/errors"
)

var (
	ErrTimeBeforeJAMCommonEra = errors.New("time before the JAM common era is invalid")
	ErrInvalidTimeSlot        = errors.New("invalid time slot")
)
