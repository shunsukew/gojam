package validator

import (
	"crypto/ed25519"

	"github.com/pkg/errors"

	"github.com/shunsukew/gojam/internal/block"
	"github.com/shunsukew/gojam/internal/entropy"
	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/internal/validator/keys"
	"github.com/shunsukew/gojam/internal/validator/safrole"
	"github.com/shunsukew/gojam/pkg/common"
	"github.com/shunsukew/gojam/pkg/crypto/bandersnatch"
)

func (s *ValidatorState) Update(
	currTimeSlot jamtime.TimeSlot,
	prevTimeSlot jamtime.TimeSlot,
	vrfOutput bandersnatch.VrfOutput, // Y(Hv): inheriting from block header
	entropyPool entropy.EntropyPool,
	ticketProofs []safrole.TicketProof,
	offenders []ed25519.PublicKey,
) (entropy.EntropyPool, *block.EpochMarker, *block.WinningTicketMarker, error) {
	var epockMarker *block.EpochMarker
	var winningTicketMarker *block.WinningTicketMarker
	prevEntropyPool := entropyPool
	prevEpochRoot := s.SafroleState.EpochRoot

	if !currTimeSlot.After(prevTimeSlot) {
		return entropyPool, epockMarker, winningTicketMarker, errors.WithMessagef(
			jamtime.ErrInvalidTimeSlot,
			"validator state update invalid timeslots. current: %d, previous: %d",
			currTimeSlot,
			prevTimeSlot,
		)
	}

	if !currTimeSlot.InTicketSubmissionPeriod() && len(ticketProofs) > 0 {
		return entropyPool, epockMarker, winningTicketMarker, errors.WithMessagef(
			safrole.ErrInvalidTicketSubmissions,
			"outside of ticket submission period but got ticket proofs",
		)
	}

	currEpoch := currTimeSlot.ToEpoch()
	prevEpoch := prevTimeSlot.ToEpoch()

	// if e' > e
	if currEpoch.After(prevEpoch) {
		// Rotate entropies
		entropyPool.RotateEntropies(vrfOutput)

		// Rotate validators
		s.RotateValidators(offenders)

		// (6.27)
		// He ≡ (η0, η1, [kb ∣k <− γk']) if e' > e
		epockMarker = newEpochMarker(&prevEntropyPool, s.ActiveValidators)

		// Determine sealing key series
		// Gray paper equation (6.24)
		// if e' = e + 1 and m >= Y, ∣γa∣=E
		if currEpoch.IsNextEpochAfter(prevEpoch) &&
			!prevTimeSlot.InTicketSubmissionPeriod() &&
			s.SafroleState.IsTicketAccumulatorFull() {
			// Regular mode
			s.SafroleState.SealingKeySeries = safrole.Tickets(safrole.OutsideInSequence(s.SafroleState.TicketsAccumulator))
		} else {
			// Fallback mode
			// Use posterior entropy η2', make sure entropy pool is updated before coming here
			fallBackKeys, err := safrole.FallbackKeysSequence(entropyPool[2], s.ActiveValidators[:])
			if err != nil {
				return entropyPool, epockMarker, winningTicketMarker, errors.WithStack(err)
			}
			s.SafroleState.SealingKeySeries = fallBackKeys
		}

		// As defined in equation (6.34), reset prior accumulator γa when e' > e
		s.SafroleState.ResetTicketsAccumulator()
	}

	// Equation (6.28)
	// Hw ≡ Z(γa) if e′ = e ∧ m < Y ≤ m′ ∧ ∣γa∣ = E
	// The winning-tickets marker Hw is the first after the end of the submission period for tickets and if the ticket accumulator is saturated,
	// then the final sequence of ticket identifiers.
	if currEpoch.Equal(prevEpoch) &&
		prevTimeSlot.InTicketSubmissionPeriod() &&
		!currTimeSlot.InTicketSubmissionPeriod() &&
		s.SafroleState.IsTicketAccumulatorFull() {
		winningTickets := safrole.Tickets(safrole.OutsideInSequence(s.SafroleState.TicketsAccumulator))
		winningTicketMarker = newWinningTicketMarker(&winningTickets)
	}

	err := s.SafroleState.AccumulateTickets(ticketProofs, prevEpochRoot, entropyPool[2])
	if err != nil {
		return entropyPool, epockMarker, winningTicketMarker, errors.WithStack(err)
	}

	return entropyPool, epockMarker, winningTicketMarker, nil
}

func newEpochMarker(entropyPool *entropy.EntropyPool, validatorKeys *[common.NumOfValidators]keys.ValidatorKey) *block.EpochMarker {
	epochMarker := &block.EpochMarker{
		Entropies: struct {
			Next    common.Hash // μ0
			Current common.Hash // μ1
		}{
			Next:    entropyPool[0],
			Current: entropyPool[1],
		},
		BandersnatchPubKeys: [common.NumOfValidators]bandersnatch.PublicKey{},
	}

	for i, validatorKey := range validatorKeys {
		epochMarker.BandersnatchPubKeys[i] = validatorKey.BandersnatchPublicKey
	}

	return epochMarker
}

func newWinningTicketMarker(winningTickets *safrole.Tickets) *block.WinningTicketMarker {
	return &block.WinningTicketMarker{
		Tickets: *winningTickets,
	}
}
