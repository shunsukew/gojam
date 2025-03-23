package jamstate

import (
	"github.com/shunsukew/gojam/internal/jamtime"
)

// σ ≡ (α,β,γ,δ,η,ι,κ,λ,ρ,τ,φ,χ,ψ,π,θ,ξ)
type State struct {
	CoreAuthorizationsPool                       // α: The core αuthorizations pool. Equation 8.1 in Gray Paper.
	RecentBlocks                                 // β: Information on the most recent βlocks.
	SafroleState                                 // γ: State concerning Safrole. Equation 6.3 in Gray Paper.
	Services                                     // δ: The (prior) state of the service accounts.
	EntropyPool                                  // η: The eηtropy accumulator and epochal raηdomness.
	ValidatorState                               // (ι, κ, λ): The state of the validators related.
	CoreWorkReportsAssignments                   // ρ: The ρending reports, per core, which are being made available prior to accumulation.
	TimeSlot                    jamtime.TimeSlot // τ: The most recent block’s τimeslot.
	CoreAuthorizationQueue                       // φ: The authorization queue.
	PrivilegedServices                           // χ: The privileged service indices.
	PastJudgements                               // ψ: Past judgments on work-reports and validators.
	ValidatorActivityStatistics                  // π: The activity statistics for the validators.
	AccumulationQueue                            // θ: The accumulation queue.
	AccumulationHistory                          // ξ: The accumulation history.
}

type CoreAuthorizationsPool struct{}

type RecentBlocks struct{}

type SafroleState struct{}

type Services struct{}

type EntropyPool struct{}

type ValidatorState struct{}

type CoreWorkReportsAssignments struct{}

type CoreAuthorizationQueue struct{}

type PrivilegedServices struct{}

type PastJudgements struct{}

type ValidatorActivityStatistics struct{}

type AccumulationQueue struct{}

type AccumulationHistory struct{}
