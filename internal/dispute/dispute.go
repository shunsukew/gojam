package dispute

import (
	"bytes"
	"crypto/ed25519"

	"github.com/pkg/errors"
	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/pkg/common"
)

const (
	GoodReport   Conclusion = "good"
	BadReport    Conclusion = "bad"
	WonkeyReport Conclusion = "wonkey"
)

// ψ ≡ (ψg, ψb, ψw, ψo)
type DisputeState struct {
	GoodReports   []common.Hash       // ψg: The set of good work reports hashes.
	BadReports    []common.Hash       // ψb: The set of bad work reports hashes.
	WonkeyReports []common.Hash       // ψw: The set of wonkey work reports hashes.
	Offenders     []ed25519.PublicKey // ψo: The set of public keys of validators who have been punished.
}

func (ds *DisputeState) containsPastReportHashes(verdicts []*Verdict) (bool, common.Hash) {
	pastReportedHashes := ds.getPastReportedHashes()
	for _, verdict := range verdicts {
		if _, ok := pastReportedHashes[verdict.WorkReportHash]; ok {
			return true, verdict.WorkReportHash
		}
	}
	return false, common.Hash{}
}

func (ds *DisputeState) getPastReportedHashes() map[common.Hash]struct{} {
	pastReportedHashes := make(map[common.Hash]struct{}, len(ds.GoodReports)+len(ds.BadReports)+len(ds.WonkeyReports))
	for _, report := range ds.GoodReports {
		pastReportedHashes[report] = struct{}{}
	}
	for _, report := range ds.BadReports {
		pastReportedHashes[report] = struct{}{}
	}
	for _, report := range ds.WonkeyReports {
		pastReportedHashes[report] = struct{}{}
	}
	return pastReportedHashes
}

func (ds *DisputeState) containsPunishedValidators(keys []ed25519.PublicKey) bool {
	punishedSet := make(map[string]struct{}, len(ds.Offenders))
	for _, offender := range ds.Offenders {
		punishedSet[common.Bytes2Hex(offender)] = struct{}{}
	}
	for _, key := range keys {
		if _, exists := punishedSet[common.Bytes2Hex(key)]; exists {
			return true
		}
	}
	return false
}

type Verdicts []*Verdict

type Verdict struct {
	WorkReportHash common.Hash
	Epoch          jamtime.Epoch
	Judgements     *Judgements // judgements from 2/3 + 1 supermajority valudators is requirement
}

type VerdictOutcome struct {
	WorkReportHash common.Hash // r
	PositiveVotes  int
	Conclusion     Conclusion
}

type Conclusion string

func (v *Verdict) TallyVotes() (*VerdictOutcome, error) {
	var positiveVotes int
	for _, judgement := range *v.Judgements {
		if judgement.Vote {
			positiveVotes++
		}
	}

	var conclusion Conclusion
	switch positiveVotes {
	case 0:
		conclusion = BadReport
	case common.NumOfMinorityValidators:
		conclusion = WonkeyReport
	case common.NumOfSuperMajorityValidators:
		conclusion = GoodReport
	default:
		return nil, errors.WithMessagef(
			ErrInvalidVerdicts,
			"verdict for report hash %s has invalid number of positive votes: %d. must be either 0, one-third, or two-thirds-plus-on",
			v.WorkReportHash, positiveVotes,
		)
	}

	return &VerdictOutcome{
		WorkReportHash: v.WorkReportHash,
		PositiveVotes:  positiveVotes,
		Conclusion:     conclusion,
	}, nil
}

func (verdicts Verdicts) isSortedNonDuplicates() bool {
	for i := 1; i < len(verdicts); i++ {
		if bytes.Compare(verdicts[i-1].WorkReportHash[:], verdicts[i].WorkReportHash[:]) != -1 {
			return false
		}
	}
	return true
}

type Judgements [common.NumOfSuperMajorityValidators]*Judgement

type Judgement struct {
	Vote           bool
	ValidatorIndex uint8
	Signature      []byte // 𝔼
}

func (j *Judgements) isSortedNonDuplicates() bool {
	for i := 1; i < len(*j); i++ {
		if (*j)[i-1].ValidatorIndex >= (*j)[i].ValidatorIndex {
			return false
		}
	}
	return true
}

type Culprits []*Culprit

// c ∈ ⟦ℍ, ℍ_E, 𝔼⟧
type Culprit struct {
	WorkReportHash common.Hash       // r
	CulpritKey     ed25519.PublicKey // k
	Signature      []byte            // 𝔼
}

func (culprits Culprits) isSortedNonDuplicates() bool {
	for i := 1; i < len(culprits); i++ {
		if bytes.Compare(culprits[i-1].CulpritKey[:], culprits[i].CulpritKey[:]) != -1 {
			return false
		}
	}
	return true
}

type Faults []*Fault

type Fault struct {
	WorkReportHash common.Hash       // r
	Vote           bool              // v
	FaultKey       ed25519.PublicKey // k
	Signature      []byte            // 𝔼
}

func (faults Faults) isSortedNonDuplicates() bool {
	for i := 1; i < len(faults); i++ {
		if bytes.Compare(faults[i-1].FaultKey[:], faults[i].FaultKey[:]) != -1 {
			return false
		}
	}
	return true
}
