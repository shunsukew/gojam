package block

import (
	"crypto/ed25519"

	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/internal/validator/safrole"
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
	EpochMarker         *EpochMarker           // He (optional, non-empty when e' > e)
	WinningTicketMarker *WinningTicketMarker   // Hw (optional, non-empty when e' > e)
	OffendersMarker     *OffendersMarker       // Ho (optional)
	BlockAuthorIndex    uint16                 // Hi: Hi ∈ NumV. V = 1023: The total number of validators.
	VRFSignature        bandersnatch.Signature // Hv
	BlockSealSignature  bandersnatch.Signature // Hs
}

type EpochMarker struct {
	Entropies struct {
		Next    common.Hash // μ0
		Current common.Hash // μ1
	}
	BandersnatchPubKeys [common.NumOfValidators]bandersnatch.PublicKey
}

type WinningTicketMarker struct {
	Tickets safrole.Tickets
}

type OffendersMarker struct {
	Offenders []ed25519.PublicKey
}
