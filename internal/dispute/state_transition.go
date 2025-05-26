package dispute

import (
	"github.com/pkg/errors"
	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/internal/validator/keys"
)

func (ds *DisputeState) Update(
	verdicts Verdicts,
	culprits Culprits,
	faults Faults,
	activeValidators []*keys.ValidatorKey,
	archivedValidators []*keys.ValidatorKey,
	timeSlot jamtime.TimeSlot,
) error {
	epoch := timeSlot.ToEpoch()

	activeValidatorsSet := ed25519keySet(activeValidators)
	archivedValidatorsSet := ed25519keySet(archivedValidators)

	if !verdicts.isSortedNonDuplicates() {
		return errors.WithMessage(ErrInvalidVerdicts, "verdicts are not sorted or contain duplicates")
	}

	// What if extrinsic contains same validator key in culprits and faults??

	if !culprits.isSortedNonDuplicates() {
		return errors.WithMessage(ErrInvalidCulprits, "culprits are not sorted or contain duplicates")
	}

	if !faults.isSortedNonDuplicates() {
		return errors.WithMessage(ErrInvalidFaults, "faults are not sorted or contain duplicates")
	}

	verdictSummaries, err := ds.SummarizeVerdicts(epoch, verdicts, activeValidators, archivedValidators)
	if err != nil {
		return errors.WithMessage(ErrInvalidVerdicts, err.Error())
	}

	culpritsByReportHash, culpritKeys, err := groupAndVerifyCulprits(culprits, verdictSummaries)
	if err != nil {
		return err
	}

	faultsByReportHash, faultKeys, err := groupAndVerifyFaults(faults, verdictSummaries)
	if err != nil {
		return err
	}

	for _, summary := range verdictSummaries {
		var validVote bool

		switch summary.ReportLabel {
		case GoodReportLabel:
			validVote = true

			// Faults should contain at least one valid entry.
			if len(faultsByReportHash[summary.WorkReportHash]) < 1 {
				return errors.WithMessagef(ErrInvalidFaults, "no valid faults for good report %s", summary.WorkReportHash)
			}
			ds.GoodReports = append(ds.GoodReports, summary.WorkReportHash)
		case BadReportLabel:
			validVote = false
			// Culprits should contain at least two valid entries.
			if len(culpritsByReportHash[summary.WorkReportHash]) < 2 {
				return errors.WithMessagef(ErrInvalidCulprits, "not enough valid culprits for bad report %s", summary.WorkReportHash)
			}
			ds.BadReports = append(ds.BadReports, summary.WorkReportHash)
		case WonkeyReportLabel:
			ds.WonkeyReports = append(ds.WonkeyReports, summary.WorkReportHash)
		default:
		}

		var effectiveValidatorsSet map[string]struct{}
		if summary.Epoch.Equal(epoch) {
			effectiveValidatorsSet = activeValidatorsSet
		} else {
			effectiveValidatorsSet = archivedValidatorsSet
		}

		for _, c := range culpritsByReportHash[summary.WorkReportHash] {
			if _, ok := effectiveValidatorsSet[string(c.CulpritKey)]; !ok {
				return errors.WithMessagef(ErrInvalidCulprits, "culprit %s is not an active or archived validator", string(c.CulpritKey))
			}
		}

		for _, f := range faultsByReportHash[summary.WorkReportHash] {
			if f.Vote == validVote {
				return errors.WithMessagef(ErrInvalidFaults, "fault %s has invalid vote: expected %t, got %t", f.WorkReportHash, validVote, f.Vote)
			}
			if _, ok := effectiveValidatorsSet[string(f.FaultKey)]; !ok {
				return errors.WithMessagef(ErrInvalidFaults, "fault %s is not an active or archived validator", string(f.FaultKey))
			}
		}
	}

	offenders := append(culpritKeys, faultKeys...)
	if ds.containsPunishedValidators(offenders) {
		return errors.New("seen validator already punished in the past")
	}
	ds.Offenders = append(ds.Offenders, offenders...)

	return nil
}
