package work

import "github.com/shunsukew/gojam/pkg/common"

// (11.2) W ≡ (s ∈ S, x ∈ X, c ∈ NC, a ∈ H, o ∈ Y, l ∈ D⟨H→H⟩, r ∈ ⟦L⟧1:I)
type WorkReport struct {
	AvailabilitySpecification *AvailabilitySpecification  // s ∈ S
	RefinementContext         []byte                      // x ∈ X
	CoreIndex                 uint8                       // c ∈ NC
	AuthorizerHash            common.Hash                 // a ∈ H
	Output                    []byte                      // o ∈ Y
	SegmentRootLookup         map[common.Hash]common.Hash // l ∈ D⟨H→H⟩
	WorkResults               []*WorkResult               // r ∈ ⟦L⟧1:I
}

// (11.5) S ≡ [ h ∈ H, l ∈ NL, u ∈ H, e ∈ H, n ∈ N ]
type AvailabilitySpecification struct {
	WorkPackageHash  common.Hash // h ∈ H
	WorkBundleLength uint32      // l ∈ NL
	ErasureRoot      common.Hash // u ∈ H
	SegmentRoot      common.Hash // e ∈ H
	SegmentCount     uint        // n ∈ N
}
