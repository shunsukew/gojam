package history

import (
	"github.com/shunsukew/gojam/pkg/common"
	"github.com/shunsukew/gojam/pkg/mmr"
)

const (
	NumOfRetainedBlocks = 8 // H: the number of blocks to retain in history
)

type RecentHistory []*RecentBlock

// (7.1) β ∈ ⟦ h ∈ H;blackboard, b ∈ ⟦H;blackboard?⟧, s ∈ H;blackboard, p ∈ D⟨H;blackboard→H;blackboard⟩ ⟧:H
type RecentBlock struct {
	HeaderHash            common.Hash                 // h ∈ H;blackboard
	StateRoot             common.Hash                 // s ∈ H;blackboard
	AccumulationResultMMR mmr.MMR                     // b ∈ ⟦H;blackboard?⟧
	WorkPackageHashes     map[common.Hash]common.Hash // p: Work package hash <> segment root mapping derived from work reports.
}
