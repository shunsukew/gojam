package workreport

import (
	"github.com/shunsukew/gojam/internal/work"
	"github.com/shunsukew/gojam/pkg/common"
)

const (
	OutOfGas           ExecError = iota // ∞
	Panic              ExecError = iota // ☇
	ReportInvalid      ExecError = iota // ⊚
	ServiceUnavailable ExecError = iota // BAD
	CodeTooBig         ExecError = iota // BIG
)

// (11.2) W ≡ (s ∈ S, x ∈ X, c ∈ NC, a ∈ H, o ∈ Y, l ∈ D⟨H→H⟩, r ∈ ⟦L⟧1:I)
type WorkReport struct {
	AvailabilitySpecification *AvailabilitySpecification  // s ∈ S
	RefinementContext         *work.RefinementContext     // x ∈ X
	CoreIndex                 uint8                       // c ∈ NC
	AuthorizerHash            common.Hash                 // a ∈ H
	Output                    []byte                      // o ∈ Y
	SegmentRootLookup         map[common.Hash]common.Hash // l ∈ D⟨H→H⟩
	WorkResults               []*WorkResult               // r ∈ ⟦L⟧1:I cannot be empty
}

// (11.5) S ≡ [ h ∈ H, l ∈ NL, u ∈ H, e ∈ H, n ∈ N ]
type AvailabilitySpecification struct {
	WorkPackageHash  common.Hash // h ∈ H
	WorkBundleLength uint32      // l ∈ NL
	ErasureRoot      common.Hash // u ∈ H
	SegmentRoot      common.Hash // e ∈ H
	SegmentCount     uint        // n ∈ N
}

// (11.6) L ≡ (s ∈ NS , c ∈ H, l ∈ H, g ∈ NG , o ∈ Y ∪ J)
type WorkResult struct {
	ServiceIndex    uint32      // s ∈ NS
	ServiceCodeHash common.Hash // c ∈ H
	PayloadHash     common.Hash // l ∈ H
	Gas             uint64      // g ∈ NG
	ExecResult      *ExecResult // o ∈ Y ∪ J
}

type ExecError int

type ExecResult struct {
	Output []byte    // Y
	Error  ExecError // J ∈ {∞, ☇, ⊚, BAD, BIG}
}
