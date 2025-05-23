package service

import (
	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/pkg/common"
)

type PreimageRequest struct {
	ServiceId ServiceId
	Preimage  common.Blob
}

type Footprint struct {
	NumOfStorageItems  uint32
	SizeOfStorageItems uint64
}

func (s *Services) Update(
	timeSlot jamtime.TimeSlot,
	preimages []*PreimageRequest,
) ([]*Footprint, error) {
	return nil, nil
}
