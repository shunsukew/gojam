package history

import (
	"github.com/shunsukew/gojam/pkg/common"
	"github.com/shunsukew/gojam/pkg/crypto"
	"github.com/shunsukew/gojam/pkg/mmr"
)

func (recentHistory *RecentHistory) Update(
	headerHash common.Hash, // H(H)
	priorStateRoot common.Hash, // Hr
	accumulationResultRoot common.Hash, // r: accumulation result root is derived from C (defined in section 12). let r = MB([s^E4(s) ⌢ E(h) ∣ (s,h) ∈ C],HK).
	workPackageHashes map[common.Hash]common.Hash, // {((gw)s)h ↦ ((gw)s)e ∣ g ∈ EG}. should be calculated from Guarantee Extrinsic work reports.
) error {
	// (7.2) β† ≡ β except β†[∣β∣ − 1]s = Hr
	if len(*recentHistory) != 0 {
		(*recentHistory)[len(*recentHistory)-1].StateRoot = priorStateRoot
	}

	// let b = A(last([[]] ⌢ [xb ∣ x <− β]), r, HK)
	var lastBlockMMR mmr.MMR
	if len(*recentHistory) > 0 {
		lastBlockMMR = (*recentHistory)[len(*recentHistory)-1].AccumulationResultMMR
	}

	accumulationResultMMR := mmr.Append(lastBlockMMR, accumulationResultRoot, crypto.Keccak256Hash)

	newRecentBlock := &RecentBlock{
		HeaderHash:            headerHash,
		StateRoot:             common.Hash{}, // empty state root as we don't know posterior state root of this block yet
		WorkPackageHashes:     workPackageHashes,
		AccumulationResultMMR: accumulationResultMMR,
	}

	*recentHistory = append(*recentHistory, newRecentBlock)
	if len(*recentHistory) > NumOfRetainedBlocks {
		*recentHistory = (*recentHistory)[len(*recentHistory)-NumOfRetainedBlocks:]
	}

	return nil
}
