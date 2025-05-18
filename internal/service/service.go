package service

import "github.com/shunsukew/gojam/pkg/common"

type ServiceId uint8 // ℕ_S

type Balance uint64 // ℕ_B

type Gas uint64 // ℕ_G

// δ ∈ D⟨NS → A⟩
type Services map[ServiceId]*ServiceAccount

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
	StorageItems map[common.Hash][]byte // s
	Preimages    map[common.Hash][]byte // p
	// LookupMeta // TODO: l
	CodeHash      common.Hash // c
	Balance       Balance     // b
	AccumulateGas Gas         // g
	OnTransferGas Gas         // m
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
