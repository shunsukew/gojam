package block

import (
	"github.com/shunsukew/gojam/internal/dispute"
	"github.com/shunsukew/gojam/internal/validator/safrole"
	workreport "github.com/shunsukew/gojam/internal/work/report"
)

// Hasing Extrinsic
// (5.4) (5.5) (5.6)
// Hx ∈ H , Hx ≡ H(E(H#(a)))
// where a = [ET(ET),EP(EP ),g,EA(EA),ED(ED)]
// and g = E(↕[E(H(w), E4(t), ↕a) ∣ (w, t, a) −< EG])

type Extrinsic struct {
	TicketsExtrinsic     // ET: Tickets, used for the mechanism which manages the selection of validators for the permissioning of block authoring.
	PreimagesExtrinsic   // EP: Static data which is presently being requested to be available for workloads to be able to fetch on demand.
	GuaranteesExtrinsic  // EG: Reports of newly completed workloads whose accuracy is guaranteed by specific validators.
	AssuarancesExtrinsic // EA: Assurances by each validator concerning which of the input data of workloads they have correctly received and are storing locally.
	DisputesExtrinsic    // ED: Information relating to disputes between validators over the validity of reports.
}

type TicketsExtrinsic struct {
	Tickets []safrole.TicketProof
}

type PreimagesExtrinsic struct{}

// EG ∈ ⟦(w ∈ W, t ∈ NT, a ∈ ⟦(NV, E)⟧₂:₃)⟧C
type GuaranteesExtrinsic struct {
	Guarantees []*workreport.Guarantee // TODO: max array length must be core count C (:C). unique per core (11.24) EG = [(gw)c | g ∈ EG].
}

type AssuarancesExtrinsic struct {
	Assurances []*workreport.Assurance // at most V number of assurances, one per validator
}

type DisputesExtrinsic struct {
	Verdicts []*dispute.Verdict // Verdicts v must be ordered by report hash
	Culprits []*dispute.Culprit // Should not include already-inside-punish-set offenders
	Faults   []*dispute.Fault   // Should not include already-inside-punish-set offenders
}
