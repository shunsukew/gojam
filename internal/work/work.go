package work

import (
	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/pkg/common"
)

type RefinementContext struct {
	AnchorHeaderHash              common.Hash      // a ∈ H
	AnchorStateRoot               common.Hash      // s ∈ H
	AnchorBeefyRoot               common.Hash      // b ∈ H
	LookupAnchorHeaderHash        common.Hash      // l ∈ H
	LookupAnchorTimeSlot          jamtime.TimeSlot // t ∈ T
	PreRequisiteWorkPackageHashes []common.Hash    // p ∈ {H}
}
