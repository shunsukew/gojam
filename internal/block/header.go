package block

import (
	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/pkg/common"
	"github.com/shunsukew/gojam/pkg/crypto/bandersnatch"
)

// Block's header
// H ≡ (Hp,Hr,Hx,Ht,He,Hw,Ho,Hi,Hv,Hs)
type Header struct {
	ParentHash          common.Hash            // Hp
	PriorStateRoot      common.Hash            // Hr
	ExtrinsicHash       common.Hash            // Hx
	TimeSlot            jamtime.TimeSlot       // Ht
	EpochMarker         *EpochMarker           // He (optional)
	WinningTicketMarker *WinningTicketMarker   // Hw (optional)
	OffendersMarker     *OffendersMarker       // Ho (optional)
	BlockAuthorIndex    uint16                 // Hi // TODO: Check maximum number, and decide uint size
	VRFSignature        bandersnatch.Signature // Hv
	BlockSealSignature  bandersnatch.Signature // Hs
}

type EpochMarker struct {
}

type WinningTicketMarker struct {
}

type OffendersMarker struct {
}
