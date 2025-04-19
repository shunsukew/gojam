package safrole

import (
	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/internal/validator/keys"
	"github.com/shunsukew/gojam/pkg/codec"
	"github.com/shunsukew/gojam/pkg/common"
	"github.com/shunsukew/gojam/pkg/crypto/bandersnatch"
	"golang.org/x/crypto/blake2b"
)

const (
	NumOfTicketEntries      = 2 // N: The number of ticket entries per validator.
	MaxTicketEntryIndex     = 1 // entry index should be 0 or 1.
	MaxTicketsInAccumulator = jamtime.TimeSlotsPerEpoch
)

type SealingKeySeriesKind interface {
	SealingKeySeries()
}

// Defined as C;blackboard in the Gray Paper
// C;blackboard ≡ [ y ∈ H, r ∈ NumN ]
type Ticket struct {
	EntryIndex uint8                  // r: r ∈ NumN.
	TicketID   bandersnatch.VrfOutput // y: y ∈ H
}

type Tickets []Ticket

func (t Tickets) SealingKeySeries() {}

type TicketProof struct {
	EntryIndex  uint8                 // r: r ∈ NumN.
	TicketProof bandersnatch.VrfProof // p: p ∈ F ̄[]γz ⟨XT ⌢ η2′ ++ r⟩
}

type FallbackKeys [jamtime.TimeSlotsPerEpoch]bandersnatch.PublicKey

func (fk FallbackKeys) SealingKeySeries() {}

type SafroleState struct {
	PendingValidators  [common.NumOfValidators]keys.ValidatorKey // γk: the set of keys which will be active in the "next" epoch and which determine the Bandersnatch ring root (EpochRoot) which authorizes tickets into the sealing-key contest for the "next" epoch.
	EpochRoot          bandersnatch.RingRoot                     // γz (γz∈YR): a Bandersnatch ring root composed with the one Bandersnatch key of each of the "next" epoch’s validators
	SealingKeySeries   SealingKeySeriesKind                      // γs: the "current" epoch’s slot-sealer series, which is either a full complement of E tickets or, in the case of a fallback mode, a series of E Bandersnatch keys.
	TicketsAccumulator Tickets                                   // γa: the ticket accumulator, a series of highest scoring ticket identifiers to be used for the "next" epoch.
}

func (s *SafroleState) IsTicketAccumulatorFull() bool {
	return len(s.TicketsAccumulator) == MaxTicketsInAccumulator
}

func (s *SafroleState) AccumulateTickets(incoming []TicketProof) error {
	if len(incoming) == 0 {
		return nil
	}

	return nil
}

func (s *SafroleState) ResetTicketsAccumulator() {
	s.TicketsAccumulator = make([]Ticket, 0, MaxTicketsInAccumulator)
}

func (s *SafroleState) ComputeRingRoot() error {
	// TODO: Implement the logic to compute the Bandersnatch ring root.

	// calcurate ring by using pending validators keys

	// s.EpochRoot = bandersnatch.RingRoot{}

	return nil
}

// OutsideIn Sequence function Z defined as equation (6.25) in the Gray Paper.
func OutsideInSequence[T any](input []T) []T {
	length := len(input)
	output := make([]T, 0, length)
	left, right := 0, length-1
	for left <= right {
		output = append(output, input[left])
		left++
		if left <= right {
			output = append(output, input[right])
			right--
		}
	}

	return output
}

// Fallback Key Sequence function F defined as equation (6.26) in the Gray Paper.
// Note: It seems function input doesn't specify the length of validator keys array. So, not infering to use common.NumOfValidators for now.
func FallbackKeysSequence(entropy common.Hash, validatorKeys []keys.ValidatorKey) (FallbackKeys, error) {
	numOfValidatorKeys := uint32(len(validatorKeys))
	fallbackKeys := FallbackKeys{}
	for i := range len(fallbackKeys) {
		iBytes, err := codec.Encode(uint32(i))
		if err != nil {
			return [jamtime.TimeSlotsPerEpoch]bandersnatch.PublicKey{}, err
		}

		hash := blake2b.Sum256(append(entropy[:], iBytes...))

		var num uint32
		err = codec.Decode(hash[:4], &num)
		if err != nil {
			return [jamtime.TimeSlotsPerEpoch]bandersnatch.PublicKey{}, err
		}

		fallbackKeys[i] = validatorKeys[num%numOfValidatorKeys].BandersnatchPublicKey
	}

	return fallbackKeys, nil
}
