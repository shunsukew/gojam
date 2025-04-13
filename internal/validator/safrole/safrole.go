package safrole

import (
	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/internal/validator/keys"
	"github.com/shunsukew/gojam/pkg/common"
	"github.com/shunsukew/gojam/pkg/crypto/bandersnatch"
)

const (
	NumOfTicketEntries      = 2 // N: The number of ticket entries per validator.
	MaxTicketEntryIndex     = 1 // entry index should be 0 or 1.
	MaxTicketsInAccumulator = jamtime.TimeSlotsPerEpoch
)

type SealingKeyKind interface {
	SealingKeyType()
}

// Defined as C;blackboard in the Gray Paper
// C;blackboard ≡ [ y ∈ H, r ∈ NumN ]
type Ticket struct {
	TicketID   bandersnatch.OutputHash // y: y ∈ H
	EntryIndex uint8                   // r: r ∈ NumN.
}

func (t Ticket) SealingKeyKind() {}

type SafroleState struct {
	PendingValidators  [common.NumOfValidators]keys.ValidatorKey // γk: the set of keys which will be active in the "next" epoch and which determine the Bandersnatch ring root (EpochRoot) which authorizes tickets into the sealing-key contest for the "next" epoch.
	EpochRoot          bandersnatch.RingRoot                     // γz (γz∈YR): a Bandersnatch ring root composed with the one Bandersnatch key of each of the "next" epoch’s validators
	SealingKeySeries   [jamtime.TimeSlotsPerEpoch]SealingKeyKind // γs: the "current" epoch’s slot-sealer series, which is either a full complement of E tickets or, in the case of a fallback mode, a series of E Bandersnatch keys.
	TicketsAccumulator []Ticket                                  // γa: the ticket accumulator, a series of highest scoring ticket identifiers to be used for the "next" epoch.
}

func (s *SafroleState) ComputeRingRoot(validtorKeys [common.NumOfValidators]keys.ValidatorKey) (bandersnatch.RingRoot, error) {
	// TODO: Implement the logic to compute the Bandersnatch ring root.

	return bandersnatch.RingRoot{}, nil
}
