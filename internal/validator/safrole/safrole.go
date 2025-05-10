package safrole

import (
	"bytes"
	"sort"

	"github.com/pkg/errors"
	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/internal/validator/keys"
	"github.com/shunsukew/gojam/pkg/common"
	"github.com/shunsukew/gojam/pkg/crypto/bandersnatch"
	"github.com/shunsukew/scale-codec-go/codec"
	"golang.org/x/crypto/blake2b"
)

const (
	MaxTicketsInAccumulator = jamtime.TimeSlotsPerEpoch

	JamTicketSeal = "jam_ticket_seal"
)

type SealingKeySeriesKind interface {
	SealingKeySeriesKind()
}

// Defined as C;blackboard in the Gray Paper
// C;blackboard ≡ [ y ∈ H, r ∈ NumN ]
type Ticket struct {
	EntryIndex uint8                  // r: r ∈ NumN.
	TicketID   bandersnatch.VrfOutput // y: y ∈ H
}

type Tickets []*Ticket

func (t Tickets) SealingKeySeriesKind() {}

func (tickets Tickets) IsSortedNonDuplicates() bool {
	for i := 1; i < len(tickets); i++ {
		if bytes.Compare(tickets[i-1].TicketID[:], tickets[i].TicketID[:]) != -1 {
			return false
		}
	}
	return true
}

func (tickets Tickets) Sort() {
	sort.Slice(tickets, func(i, j int) bool {
		return bytes.Compare(tickets[i].TicketID[:], tickets[j].TicketID[:]) == -1
	})
}

type TicketProof struct {
	EntryIndex  uint8                  // r: r ∈ NumN.
	TicketProof bandersnatch.Signature // p: p ∈ F ̄[]γz ⟨XT ⌢ η2′ ++ r⟩
}

type FallbackKeys [jamtime.TimeSlotsPerEpoch]bandersnatch.PublicKey

func (fk *FallbackKeys) SealingKeySeriesKind() {}

type SafroleState struct {
	PendingValidators  *[common.NumOfValidators]*keys.ValidatorKey // γk: the set of keys which will be active in the "next" epoch and which determine the Bandersnatch ring root (EpochRoot) which authorizes tickets into the sealing-key contest for the "next" epoch.
	EpochRoot          *bandersnatch.RingCommitment                // γz (γz∈YR): a Bandersnatch ring root composed with the one Bandersnatch key of each of the "next" epoch’s validators
	SealingKeySeries   SealingKeySeriesKind                        // γs: the "current" epoch’s slot-sealer series, which is either a full complement of E tickets or, in the case of a fallback mode, a series of E Bandersnatch keys.
	TicketsAccumulator Tickets                                     // γa: the ticket accumulator, a series of highest scoring ticket identifiers to be used for the "next" epoch.
}

func (s *SafroleState) IsTicketAccumulatorFull() bool {
	return len(s.TicketsAccumulator) == MaxTicketsInAccumulator
}

func (s *SafroleState) AccumulateTickets(ticketProofs []TicketProof, priorEpochRoot *bandersnatch.RingCommitment, entropy common.Hash) error {
	if len(ticketProofs) == 0 {
		return nil
	}

	if len(ticketProofs) > MaxTicketsInExtrinsic {
		return errors.WithMessage(ErrInvalidTicketSubmissions, "too many tickets in extrinsic")
	}

	priorAccumulatedTicketIDs := make(map[bandersnatch.VrfOutput]struct{}, len(s.TicketsAccumulator))
	for _, ticket := range s.TicketsAccumulator {
		priorAccumulatedTicketIDs[ticket.TicketID] = struct{}{}
	}

	newTickets := make([]*Ticket, len(ticketProofs))
	for i, ticketProof := range ticketProofs {
		if ticketProof.EntryIndex > MaxTicketEntryIndex {
			return errors.WithMessage(ErrInvalidTicketSubmissions, "ticket entry index is invalid")
		}

		vrfOutput, err := ticketProof.TicketProof.Verify(
			buildTicketSealInput(entropy, ticketProof.EntryIndex),
			[]byte{},
			priorEpochRoot,
		)
		if err != nil {
			return errors.WithStack(err)
		}

		if _, found := priorAccumulatedTicketIDs[vrfOutput]; found {
			return errors.WithMessagef(ErrInvalidTicketSubmissions, "ticke already exists in accumulator")
		}

		newTickets[i] = &Ticket{
			EntryIndex: ticketProof.EntryIndex,
			TicketID:   vrfOutput,
		}
	}

	// Ensure newTickets are already ordered by ticket id and no duplicates
	// Equation (6.32) n = [xy _ x ∈ n]
	if !Tickets(newTickets).IsSortedNonDuplicates() {
		return errors.WithMessage(ErrInvalidTicketSubmissions, "submitted tickets are not sorted or have duplicates")
	}

	newTicketsAccumulator := make([]*Ticket, len(s.TicketsAccumulator)+len(newTickets))
	copy(newTicketsAccumulator, s.TicketsAccumulator)
	copy(newTicketsAccumulator[len(s.TicketsAccumulator):], newTickets)

	// Equation (6.34), sort the tickets and keep the top K tickets
	Tickets(newTicketsAccumulator).Sort()
	if len(newTicketsAccumulator) > MaxTicketsInAccumulator {
		newTicketsAccumulator = newTicketsAccumulator[:MaxTicketsInAccumulator]
	}
	s.TicketsAccumulator = newTicketsAccumulator

	// Equation (6.35)
	// Ensure all newly submitted tickets are added to the accumulator
	accumulatedTicketIDs := make(map[bandersnatch.VrfOutput]struct{}, len(s.TicketsAccumulator))
	for _, ticket := range s.TicketsAccumulator {
		accumulatedTicketIDs[ticket.TicketID] = struct{}{}
	}
	for _, ticket := range newTickets {
		if _, found := accumulatedTicketIDs[ticket.TicketID]; !found {
			return errors.WithMessage(ErrInvalidTicketSubmissions, "useless tickets were included")
		}
	}

	return nil
}

func buildTicketSealInput(entropy common.Hash, entryIndex uint8) []byte {
	data := []byte(JamTicketSeal)
	data = append(data, entropy[:]...)
	data = append(data, byte(entryIndex))
	return data
}

func (s *SafroleState) ResetTicketsAccumulator() {
	s.TicketsAccumulator = make([]*Ticket, 0, MaxTicketsInAccumulator)
}

func (s *SafroleState) ComputeRingRoot() error {
	publicKeys := make([]bandersnatch.PublicKey, len(s.PendingValidators))
	for i, validator := range s.PendingValidators {
		publicKeys[i] = validator.BandersnatchPublicKey
	}

	ringCommitment, err := bandersnatch.NewRingCommitment(publicKeys)
	if err != nil {
		return errors.WithStack(err)
	}

	s.EpochRoot = ringCommitment

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
func FallbackKeysSequence(entropy common.Hash, validatorKeys []*keys.ValidatorKey) (*FallbackKeys, error) {
	numOfValidatorKeys := uint32(len(validatorKeys))
	fallbackKeys := &FallbackKeys{}
	for i := range len(fallbackKeys) {
		// TODO: Replace to own JAM codec implementation
		fallbackKeyIndexBytes := make([]byte, 4)
		var err error
		if i != 0 {
			offsetBytes, err := codec.IntToBytes(uint32(i))
			if err != nil {
				return &FallbackKeys{}, errors.WithStack(err)
			}
			fallbackKeyIndexBytes = offsetBytes.GetAll()
		}

		hash := blake2b.Sum256(append(entropy[:], fallbackKeyIndexBytes...))

		var num uint32
		bytes, err := codec.NewBytes(hash[:])
		if err != nil {
			return &FallbackKeys{}, errors.WithStack(err)
		}
		decodedU32Num, err := bytes.ToUint32()
		if err != nil {
			return &FallbackKeys{}, errors.WithStack(err)
		}
		num = uint32(decodedU32Num)

		fallbackKeys[i] = validatorKeys[num%numOfValidatorKeys].BandersnatchPublicKey
	}

	return fallbackKeys, nil
}
