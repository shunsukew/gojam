package dispute

import (
	"bytes"
	"crypto/ed25519"

	"github.com/pkg/errors"
	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/internal/validator/keys"
	"github.com/shunsukew/gojam/pkg/common"
	"github.com/shunsukew/gojam/pkg/crypto"
)

const (
	GoodReportLabel   ReportLabel = "good"
	BadReportLabel    ReportLabel = "bad"
	WonkeyReportLabel ReportLabel = "wonkey"
)

// ψ ≡ (ψg, ψb, ψw, ψo)
type DisputeState struct {
	GoodReports   []common.Hash       // ψg: The set of good work reports hashes.
	BadReports    []common.Hash       // ψb: The set of bad work reports hashes.
	WonkeyReports []common.Hash       // ψw: The set of wonkey work reports hashes.
	Offenders     []ed25519.PublicKey // ψo: The set of public keys of validators who have been punished.
}

func (ds *DisputeState) getPastWorkReportHashes() map[common.Hash]struct{} {
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

type VerdictSummary struct {
	WorkReportHash common.Hash
	Epoch          jamtime.Epoch
	PositiveVotes  int
	ReportLabel    ReportLabel
}

type ReportLabel string

func (ds *DisputeState) SummarizeVerdicts(
	epoch jamtime.Epoch,
	verdicts Verdicts,
	activeValidators, archivedValidators []*keys.ValidatorKey,
) (map[common.Hash]*VerdictSummary, error) {
	verdictSummaries := make(map[common.Hash]*VerdictSummary, len(verdicts))
	pastReported := ds.getPastWorkReportHashes()

	for _, v := range verdicts {
		// work report hash should not be included if it has been reported in the past
		if _, exists := pastReported[v.WorkReportHash]; exists {
			return nil, errors.WithMessagef(ErrInvalidVerdicts, "verdict %s has already been reported in the past", v.WorkReportHash.ToHex())
		}

		if !v.Judgements.isSortedNonDuplicates() {
			return nil, errors.WithMessagef(ErrInvalidVerdicts, "judgements in verdict %s are not sorted or contain duplicates", v.WorkReportHash.ToHex())
		}

		var effectiveValidators []*keys.ValidatorKey
		if epoch.Equal(v.Epoch) {
			effectiveValidators = activeValidators
		} else if epoch.IsNextEpochAfter(v.Epoch) {
			effectiveValidators = archivedValidators
		} else {
			return nil, errors.WithMessagef(ErrInvalidVerdicts, "verdict %s has an invalid epoch: %d, expected %d or %d", v.WorkReportHash.ToHex(), v.Epoch, epoch, epoch+1)
		}

		for _, j := range v.Judgements {
			pubKey := effectiveValidators[j.ValidatorIndex].Ed25519PublicKey
			var msg []byte
			if j.Vote {
				msg = append([]byte(crypto.JamValidJudgementStatement), v.WorkReportHash[:]...)
			} else {
				msg = append([]byte(crypto.JamInvalidJudgementStatement), v.WorkReportHash[:]...)
			}
			if !ed25519.Verify(pubKey, msg, j.Signature) {
				return nil, errors.WithMessagef(ErrInvalidVerdicts, "verdict %s has an invalid cryptonature from validator %d", v.WorkReportHash.ToHex(), j.ValidatorIndex)
			}
		}

		summary, err := v.TallyVotes()
		if err != nil {
			return nil, errors.WithMessagef(ErrInvalidVerdicts, "failed to tally votes for verdict %s: %v", v.WorkReportHash, err)
		}

		verdictSummaries[v.WorkReportHash] = summary
	}

	return verdictSummaries, nil
}

func (v *Verdict) TallyVotes() (*VerdictSummary, error) {
	var positiveVotes int
	for _, judgement := range *v.Judgements {
		if judgement.Vote {
			positiveVotes++
		}
	}

	var label ReportLabel
	switch positiveVotes {
	case 0:
		label = BadReportLabel
	case common.NumOfMinorityValidators:
		label = WonkeyReportLabel
	case common.NumOfSuperMajorityValidators:
		label = GoodReportLabel
	default:
		return nil, errors.WithMessagef(
			ErrInvalidVerdicts,
			"verdict for report hash %s has invalid number of positive votes: %d. must be either 0, one-third, or two-thirds-plus-on",
			v.WorkReportHash, positiveVotes,
		)
	}

	return &VerdictSummary{
		WorkReportHash: v.WorkReportHash,
		Epoch:          v.Epoch,
		PositiveVotes:  positiveVotes,
		ReportLabel:    label,
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
	ValidatorIndex uint32
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

func ed25519keySet(vs []*keys.ValidatorKey) map[string]struct{} {
	out := make(map[string]struct{}, len(vs))
	for _, v := range vs {
		out[string(v.Ed25519PublicKey)] = struct{}{}
	}
	return out
}

func groupAndVerifyCulprits(
	culprits Culprits,
	summaries map[common.Hash]*VerdictSummary,
) (map[common.Hash][]*Culprit, []ed25519.PublicKey, error) {
	groupByReportHash := make(map[common.Hash][]*Culprit, len(culprits))
	culpritKeys := make([]ed25519.PublicKey, len(culprits))

	for i, c := range culprits {
		if _, ok := summaries[c.WorkReportHash]; !ok {
			return nil, nil, errors.WithMessagef(
				ErrInvalidCulprits,
				"culprit %s work report hash %s does not match any verdict", string(c.CulpritKey), c.WorkReportHash.ToHex(),
			)
		}

		msg := append([]byte(crypto.JamGuaranteeStatement), c.WorkReportHash[:]...)
		if !ed25519.Verify(c.CulpritKey, msg, c.Signature) {
			return nil, nil, errors.WithMessagef(
				ErrInvalidCulprits,
				"culprit %s with work report %s has invalid signature", string(c.CulpritKey), c.WorkReportHash,
			)
		}
		groupByReportHash[c.WorkReportHash] = append(groupByReportHash[c.WorkReportHash], c)
		culpritKeys[i] = c.CulpritKey
	}
	return groupByReportHash, culpritKeys, nil
}

func groupAndVerifyFaults(
	faults Faults,
	summaries map[common.Hash]*VerdictSummary,
) (map[common.Hash][]*Fault, []ed25519.PublicKey, error) {
	groupByReportHash := make(map[common.Hash][]*Fault, len(faults))
	faultKeys := make([]ed25519.PublicKey, len(faults))

	for i, f := range faults {
		if _, ok := summaries[f.WorkReportHash]; !ok {
			return nil, nil, errors.WithMessagef(
				ErrInvalidFaults,
				"fault %s with work report %s does not match any verdict", string(f.FaultKey), f.WorkReportHash.ToHex(),
			)
		}

		stmt := crypto.JamInvalidJudgementStatement
		if f.Vote {
			stmt = crypto.JamValidJudgementStatement
		}
		msg := append([]byte(stmt), f.WorkReportHash[:]...)
		if !ed25519.Verify(f.FaultKey, msg, f.Signature) {
			return nil, nil, errors.WithMessagef(
				ErrInvalidFaults,
				"fault %s with work report %s has invalid signature", string(f.FaultKey), f.WorkReportHash,
			)
		}

		groupByReportHash[f.WorkReportHash] = append(groupByReportHash[f.WorkReportHash], f)
		faultKeys[i] = f.FaultKey
	}

	return groupByReportHash, faultKeys, nil
}
