package service

import (
	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/pkg/common"
)

const (
	MaxPreimageAvailabilityHistorySize = 3
)

type ServiceId uint8 // ℕ_S

type Balance uint64 // ℕ_B

type Gas uint64 // ℕ_G

// δ ∈ D⟨NS → A⟩
type Services struct {
	services map[ServiceId]*ServiceAccount
}

type PreimageAvailabilityHistory []jamtime.TimeSlot

// A ≡ (
//
//	s ∈ D⟨H → Y⟩,
//	p ∈ D⟨H → Y⟩,
//	l ∈ D⟨(H, N_L) → ⟦N_T⟧：₃⟩,
//	c ∈ H,
//	b ∈ ℕ_B,
//	g ∈ ℕ_G,
//	m ∈ ℕ_G
//
// )
type ServiceAccount struct {
	StorageItems  map[common.Hash]common.Blob                  // s
	Preimages     map[common.Hash]common.Blob                  // p
	PreimageMeta  map[PreimageMeta]PreimageAvailabilityHistory // l
	CodeHash      common.Hash                                  // c
	Balance       Balance                                      // b
	AccumulateGas Gas                                          // g
	OnTransferGas Gas                                          // m
}

type PreimageMeta struct {
	Hash       common.Hash
	BlobLength common.BlobLength
}

// Gray paper (9.4)
// The code c of a service account is represented by a hash which, if the service is to be functional, must be present within its preimage lookup
//
//	∀a ∈ A : a_c ≡ {
//	   a_p[a_c]  if a_c ∈ a_p
//	   ∅      otherwise
//	}
func (s *ServiceAccount) GetServiceCode() []byte {
	if code, ok := s.Preimages[s.CodeHash]; ok {
		return code
	}
	return nil
}

// `LookupPreimage` is historical lookup function Λ which determines whether the preimage of some hash h was available for lookup
// by some service account a at some timeslot t, and if so, provide its preimage.
//
// defined as Λ in the gray paper (9.5)
func (s *ServiceAccount) LookupPreimage(preimageHash common.Hash, timeSlot jamtime.TimeSlot) common.Blob {
	preimage, ok := s.Preimages[preimageHash]
	if !ok {
		return nil
	}

	preimageMeta := PreimageMeta{
		Hash:       preimageHash,
		BlobLength: common.BlobLength(len(preimage)),
	}

	availabilityHistory := s.PreimageMeta[preimageMeta]
	if !availabilityHistory.isPreimageAvailableAt(timeSlot) {
		return nil
	}

	return preimage
}

// `isPreimageAvailableAt` checks if the preimage is available at the given time slot.
// ● h = []: The preimage is requested, but has not yet been supplied.
// ● h ∈ ⟦ℕ_T⟧1 : The preimage is available and has been from time h0.
// ● h ∈ ⟦ℕ_T⟧2 : The previously available preimage is now unavailable since time h1. It had been available from time h0.
// ● h ∈ ⟦ℕ_T⟧3 : The preimage is available and has been from time h2. It had previously been available from time h0 until time h1.
// Avaibality history length should be less than or equal to 3, if it is more than 3, recognize it as invalid.
func (history PreimageAvailabilityHistory) isPreimageAvailableAt(timeSlot jamtime.TimeSlot) bool {
	if len(history) == 0 {
		return false
	}

	switch len(history) {
	case 1:
		return history[0] <= timeSlot
	case 2:
		return history[0] <= timeSlot && timeSlot < history[1]
	case 3:
		return (history[0] <= timeSlot && timeSlot < history[1]) || history[2] <= timeSlot
	}

	return false
}
