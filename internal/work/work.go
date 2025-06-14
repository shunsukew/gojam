package work

import (
	"github.com/pkg/errors"
	"github.com/shunsukew/gojam/internal/history"
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

func (rc *RefinementContext) ValidateAnchors(timeSlot jamtime.TimeSlot, recentBlocks *history.RecentHistory) error {
	var anchorBlockExists bool
	for _, block := range *recentBlocks {
		if rc.AnchorHeaderHash == block.HeaderHash &&
			rc.AnchorStateRoot == block.StateRoot &&
			rc.AnchorBeefyRoot == block.AccumulationResultMMR.SuperPeak() {
			anchorBlockExists = true
			break
		}
	}

	if !anchorBlockExists {
		return errors.WithMessagef(ErrInvalidRefinementContext, "anchor block %s does not exist in recent blocks", rc.AnchorHeaderHash)
	}

	if rc.LookupAnchorTimeSlot < timeSlot-jamtime.MaxLookupAnchorAge {
		return errors.WithMessagef(ErrInvalidRefinementContext, "lookup anchor time slot %d is too old, must be within %d time slots from current time slot %d",
			rc.LookupAnchorTimeSlot, jamtime.MaxLookupAnchorAge, timeSlot)
	}

	// TODO: Check lookup anchor requirements

	return nil
}
