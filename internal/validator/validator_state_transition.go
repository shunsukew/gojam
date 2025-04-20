package validator

import (
	"crypto/ed25519"

	"github.com/pkg/errors"

	"github.com/shunsukew/gojam/internal/block"
	"github.com/shunsukew/gojam/internal/entropy"
	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/internal/validator/safrole"
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
	if !currTimeSlot.After(prevTimeSlot) {
		return entropyPool, nil, nil, errors.WithMessagef(
			jamtime.ErrInvalidTimeSlot,
			"validator state update invalid timeslots. current: %d, previous: %d",
			currTimeSlot,
			prevTimeSlot,
		)
	}

	if !currTimeSlot.InTicketSubmissionPeriod() && len(ticketProofs) > 0 {
		return entropyPool, nil, nil, errors.WithMessagef(
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

		// Determine sealing key series
		// Gray paper equation (6.24)
		// if e' = e + 1 and m >= Y, ∣γa∣=E
		if currEpoch.IsNextEpoch(prevEpoch) &&
			!prevTimeSlot.InTicketSubmissionPeriod() &&
			s.SafroleState.IsTicketAccumulatorFull() {
			// Regular mode
			s.SafroleState.SealingKeySeries = safrole.Tickets(safrole.OutsideInSequence(s.SafroleState.TicketsAccumulator))
		} else {
			// Fallback mode
			// Use posterior entropy η2', make sure entropy pool is updated before coming here
			fallBackKeys, err := safrole.FallbackKeysSequence(entropyPool[2], s.ActiveValidators[:])
			if err != nil {
				return entropyPool, nil, nil, errors.WithStack(err)
			}
			s.SafroleState.SealingKeySeries = fallBackKeys
		}

		// As defined in equation (6.34), reset prior accumulator γa when e' > e
		s.SafroleState.ResetTicketsAccumulator()
	}

	err := s.SafroleState.AccumulateTickets(ticketProofs)
	if err != nil {
		return entropyPool, nil, nil, errors.WithStack(err)
	}

	return entropyPool, nil, nil, nil
}
