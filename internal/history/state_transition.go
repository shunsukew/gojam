package history

import (
	"github.com/shunsukew/gojam/internal/work"
	"github.com/shunsukew/gojam/pkg/common"
)

// "input": {
// "header_hash": "0xad6862875431e427df25066819b82c648cf0c0d920904d58391a36a95bd9d481",
// "parent_state_root": "0xa6aae15dfd6389e8f18e72a9dd6c03071e73c9a7f47df27415aaca0de068cb50",
// "accumulate_root": "0xa983417440b618f29ed0b7fa65212fce2d363cb2b2c18871a05c4f67217290b0",
// "work_packages": [
// {
// "hash": "0x1b03bc6eda0326c35df1b3f80fb1590016d29e1e9cef9b0b35853a1f6d069d7f",
// "exports_root": "0x7d06ce0167ea77740512095c9f269f391ca620aa609a509fd5c979a5c0bfd4c0"
// }
// ]
// },

func (recentHistory *RecentHistory) Update(
	headerHash common.Hash, // H(H)
	priorStateRoot common.Hash, // Hr
	accumulationResultRoot common.Hash,
	workPackages []*work.WorkPackage,
) error {
	// (7.2) β† ≡ β except β†[∣β∣ − 1]s = Hr
	if len(*recentHistory) != 0 {
		(*recentHistory)[len(*recentHistory)-1].StateRoot = priorStateRoot
	}

	newRecentBlock := &RecentBlock{
		HeaderHash: headerHash,
		StateRoot:  common.Hash{}, // empty state root as we don't know posterior state root of this block yet
	}

	*recentHistory = append(*recentHistory, newRecentBlock)
	if len(*recentHistory) > NumOfRetainedBlocks {
		*recentHistory = (*recentHistory)[1:]
	}

	return nil
}
