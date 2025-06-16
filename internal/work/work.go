package work

import (
	"github.com/pkg/errors"
	"github.com/shunsukew/gojam/internal/history"
	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/pkg/common"
	"github.com/shunsukew/gojam/pkg/safemath"
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
	var anchorBlock *history.RecentBlock
	for _, block := range *recentBlocks {
		if rc.AnchorHeaderHash == block.HeaderHash {
			anchorBlock = block
			break
		}
	}
	if anchorBlock == nil {
		return errors.WithMessagef(ErrInvalidRefinementContext, "anchor header hash %s does not exist in recent blocks", rc.AnchorHeaderHash.ToHex())
	}
	if rc.AnchorStateRoot != anchorBlock.StateRoot {
		return errors.WithMessagef(ErrInvalidRefinementContext, "anchor state root %s does not match state root %s for anchor header hash %s",
			rc.AnchorStateRoot.ToHex(), anchorBlock.StateRoot.ToHex(), rc.AnchorHeaderHash.ToHex())
	}
	if rc.AnchorBeefyRoot != anchorBlock.AccumulationResultMMR.SuperPeak() {
		anchorBlockBeefyRoot := anchorBlock.AccumulationResultMMR.SuperPeak()
		return errors.WithMessagef(ErrInvalidRefinementContext, "anchor beefy root %s does not match beefy root %s for anchor header hash %s",
			rc.AnchorBeefyRoot.ToHex(), anchorBlockBeefyRoot.ToHex(), rc.AnchorHeaderHash.ToHex())
	}

	if rc.LookupAnchorTimeSlot < safemath.SaturatingSub(timeSlot, jamtime.MaxLookupAnchorAge) {
		return errors.WithMessagef(ErrInvalidRefinementContext, "lookup anchor time slot %d is too old, must be within %d time slots from current time slot %d",
			rc.LookupAnchorTimeSlot, jamtime.MaxLookupAnchorAge, timeSlot)
	}

	// TODO: Check lookup anchor requirements

	return nil
}
