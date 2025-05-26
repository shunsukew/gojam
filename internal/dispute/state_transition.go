package dispute

import (
	"crypto/ed25519"

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
) (offendersMark []ed25519.PublicKey, err error) {
	epoch := timeSlot.ToEpoch()

	activeValidatorsSet := ed25519keySet(activeValidators)
	archivedValidatorsSet := ed25519keySet(archivedValidators)

	if !verdicts.isSortedNonDuplicates() {
		return nil, errors.WithMessage(ErrInvalidVerdicts, "verdicts are not sorted or contain duplicates")
	}

	// What if extrinsic contains same validator key in culprits and faults??

	if !culprits.isSortedNonDuplicates() {
		return nil, errors.WithMessage(ErrInvalidCulprits, "culprits are not sorted or contain duplicates")
	}

	if !faults.isSortedNonDuplicates() {
		return nil, errors.WithMessage(ErrInvalidFaults, "faults are not sorted or contain duplicates")
	}

	verdictSummaries, err := ds.SummarizeVerdicts(epoch, verdicts, activeValidators, archivedValidators)
	if err != nil {
		return nil, errors.WithMessage(ErrInvalidVerdicts, err.Error())
	}

	culpritsByReportHash, culpritKeys, err := groupAndVerifyCulprits(culprits, verdictSummaries)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	faultsByReportHash, faultKeys, err := groupAndVerifyFaults(faults, verdictSummaries)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	offenders := append(culpritKeys, faultKeys...)

	for _, summary := range verdictSummaries {
		var expectedVote bool
		switch summary.ReportLabel {
		case GoodReportLabel:
			expectedVote = true
			// Faults should contain at least one valid entry.
			if len(faultsByReportHash[summary.WorkReportHash]) < 1 {
				return nil, errors.WithMessagef(ErrInvalidFaults, "no valid faults for good report %s", summary.WorkReportHash)
			}
			ds.GoodReports = append(ds.GoodReports, summary.WorkReportHash)
		case BadReportLabel:
			expectedVote = false
			// Culprits should contain at least two valid entries.
			if len(culpritsByReportHash[summary.WorkReportHash]) < 2 {
				return nil, errors.WithMessagef(ErrInvalidCulprits, "not enough valid culprits for bad report %s", summary.WorkReportHash)
			}
			ds.BadReports = append(ds.BadReports, summary.WorkReportHash)
		case WonkeyReportLabel:
			// TODO: wonkey report can have culprits and faults?
			ds.WonkeyReports = append(ds.WonkeyReports, summary.WorkReportHash)
			if len(offenders) > 0 {
				// TODO: check if it is correct?
				return nil, errors.WithMessagef(ErrInvalidVerdicts, "wonkey report %s should not have offenders", summary.WorkReportHash)
			}
			continue
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
				return nil, errors.WithMessagef(ErrInvalidCulprits, "culprit %s is not an active or archived validator", string(c.CulpritKey))
			}
		}

		for _, f := range faultsByReportHash[summary.WorkReportHash] {
			// fault should have an against vote of the verdict result
			if f.Vote == expectedVote {
				return nil, errors.WithMessagef(ErrInvalidFaults, "fault %s has invalid vote: expected %t, got %t", f.WorkReportHash, expectedVote, f.Vote)
			}
			if _, ok := effectiveValidatorsSet[string(f.FaultKey)]; !ok {
				return nil, errors.WithMessagef(ErrInvalidFaults, "fault %s is not an active or archived validator", string(f.FaultKey))
			}
		}
	}

	if ds.containsPunishedValidators(offenders) {
		return nil, errors.New("seen validator already punished in the past")
	}
	ds.Offenders = append(ds.Offenders, offenders...)

	return offenders, nil
}
