package dispute

import (
	"crypto/ed25519"

	"github.com/pkg/errors"
	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/internal/validator/keys"
	"github.com/shunsukew/gojam/pkg/common"
)

// TODO: Remove active validators and archived validators from Update method.
// effective validators Key set k should be determined before the dispute state transition.
//
// TODO: Signature checks
func (ds *DisputeState) Update(
	verdicts Verdicts,
	culprits Culprits,
	faults Faults,
	activeValidators []*keys.ValidatorKey,
	archivedValidators []*keys.ValidatorKey,
	timeSlot jamtime.TimeSlot,
) error {
	epoch := timeSlot.ToEpoch()

	if !verdicts.isSortedNonDuplicates() {
		return errors.WithMessage(ErrInvalidVerdicts, "verdicts are not sorted or contain duplicates")
	}

	if !culprits.isSortedNonDuplicates() {
		return errors.WithMessage(ErrInvalidCulprits, "culprits are not sorted or contain duplicates")
	}

	if !faults.isSortedNonDuplicates() {
		return errors.WithMessage(ErrInvalidFaults, "faults are not sorted or contain duplicates")
	}

	if reported, reportHash := ds.containsPastReportHashes(verdicts); reported {
		return errors.WithMessagef(ErrInvalidVerdicts, "verdicts have already been reported in the past: %s", reportHash)
	}

	reportHashes := make(map[common.Hash]struct{}, len(verdicts))
	verdictsOutcomes := make([]*VerdictOutcome, len(verdicts))
	for i, v := range verdicts {
		if !v.Judgements.isSortedNonDuplicates() {
			return errors.WithMessagef(ErrInvalidVerdicts, "judgements in verdict %s are not sorted or contain duplicates", v.WorkReportHash.ToHex())
		}

		// var effectiveKeys []*keys.ValidatorKey
		if epoch.Equal(v.Epoch) {
			// effectiveKeys = activeValidators
		} else if epoch.IsNextEpochAfter(v.Epoch) {
			// effectiveKeys = archivedValidators
		} else {
			return errors.WithMessagef(ErrInvalidVerdicts, "verdict %s has an invalid epoch: %d, expected %d or %d", v.WorkReportHash.ToHex(), v.Epoch, epoch, epoch+1)
		}

		verdictOutcome, err := v.TallyVotes()
		if err != nil {
			return errors.WithMessagef(ErrInvalidVerdicts, "failed to tally votes for verdict %s: %v", v.WorkReportHash, err)
		}

		verdictsOutcomes[i] = verdictOutcome
		reportHashes[verdictOutcome.WorkReportHash] = struct{}{}
	}

	offenders := make([]ed25519.PublicKey, 0, len(culprits)+len(faults))
	calpritsSet := map[common.Hash][]*Culprit{}
	for _, c := range culprits {
		if _, ok := reportHashes[c.WorkReportHash]; !ok {
			return errors.WithMessagef(ErrInvalidCulprits, "culprit %s does not match any report hash in verdicts", c.WorkReportHash)
		}
		offenders = append(offenders, ed25519.PublicKey(c.CulpritKey))
		calpritsSet[c.WorkReportHash] = append(calpritsSet[c.WorkReportHash], c)
	}
	faultsSet := map[common.Hash][]*Fault{}
	for _, f := range faults {
		if _, ok := reportHashes[f.WorkReportHash]; !ok {
			return errors.WithMessagef(ErrInvalidFaults, "fault %s does not match any report hash in verdicts", f.WorkReportHash)
		}
		offenders = append(offenders, ed25519.PublicKey(f.FaultKey))
		faultsSet[f.WorkReportHash] = append(faultsSet[f.WorkReportHash], f)
	}

	if ds.containsPunishedValidators(offenders) {
		return errors.New("seen validator already punished in the past")
	}

	for _, outcome := range verdictsOutcomes {
		var validVote bool

		switch outcome.Conclusion {
		case GoodReport:
			validVote = true
			// Faults should contain at least one valid entry.
			if len(faultsSet[outcome.WorkReportHash]) < 1 {
				return errors.WithMessagef(ErrInvalidFaults, "no valid faults for good report %s", outcome.WorkReportHash)
			}
			ds.GoodReports = append(ds.GoodReports, outcome.WorkReportHash)
		case BadReport:
			validVote = false
			// Culprits should contain at least two valid entries.
			if len(calpritsSet[outcome.WorkReportHash]) < 2 {
				return errors.WithMessagef(ErrInvalidCulprits, "not enough valid culprits for bad report %s", outcome.WorkReportHash)
			}
			ds.BadReports = append(ds.BadReports, outcome.WorkReportHash)
		case WonkeyReport:
			ds.WonkeyReports = append(ds.WonkeyReports, outcome.WorkReportHash)
		default:
		}

		for _, f := range faultsSet[outcome.WorkReportHash] {
			if f.Vote == validVote {
				return errors.WithMessagef(ErrInvalidFaults, "fault %s has invalid vote: expected %t, got %t", f.WorkReportHash, validVote, f.Vote)
			}
		}
	}

	ds.Offenders = append(ds.Offenders, offenders...)

	return nil
}
