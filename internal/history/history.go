package history

import "github.com/shunsukew/gojam/pkg/common"

const (
	NumOfRetainedBlocks = 8 // H: the number of blocks to retain in history
)

type RecentHistory []*RecentBlock

// (7.1) β ∈ ⟦ h ∈ H;blackboard, b ∈ ⟦H;blackboard?⟧, s ∈ H;blackboard, p ∈ D⟨H;blackboard→H;blackboard⟩ ⟧:H
type RecentBlock struct {
	HeaderHash            common.Hash
	StateRoot             common.Hash
	AccumulationResultMMR *MMR
	WorkPackageHashes     map[common.Hash]common.Hash // Work package hash <> segment root mapping derived from work reports.
}

type MMR struct {
}
