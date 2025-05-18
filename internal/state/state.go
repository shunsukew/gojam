package jamstate

import (
	authpool "github.com/shunsukew/gojam/internal/authorizer/pool"
	authqueue "github.com/shunsukew/gojam/internal/authorizer/queue"
	"github.com/shunsukew/gojam/internal/service"

	"github.com/shunsukew/gojam/internal/entropy"
	"github.com/shunsukew/gojam/internal/history"
	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/internal/validator"
)

// σ ≡ (α,β,γ,δ,η,ι,κ,λ,ρ,τ,φ,χ,ψ,π,θ,ξ)
type State struct {
	AuthorizerPools             authpool.AuthorizerPools   // α: The core αuthorizations pool. Equation 8.1 in Gray Paper.
	RecentHistory               history.RecentHistory      // β: Information on the most recent βlocks.
	Services                    service.Services           // δ: The (prior) state of the service accounts.
	EntropyPool                 entropy.EntropyPool        // η: The eηtropy accumulator and epochal raηdomness.
	ValidatorState              validator.ValidatorState   // (ι, κ, λ): The state of the validators related. & γ: State concerning Safrole. Equation 6.3 in Gray Paper.
	CoreWorkReportsAssignments                             // ρ: The ρending reports, per core, which are being made available prior to accumulation.
	TimeSlot                    jamtime.TimeSlot           // τ: The most recent block’s τimeslot.
	AuthorizerQueues            authqueue.AuthorizerQueues // φ: The authorization queue.
	PrivilegedServices                                     // χ: The privileged service indices.
	PastJudgements                                         // ψ: Past judgments on work-reports and validators.
	ValidatorActivityStatistics                            // π: The activity statistics for the validators.
	AccumulationQueue                                      // θ: The accumulation queue.
	AccumulationHistory                                    // ξ: The accumulation history.
}

type CoreWorkReportsAssignments struct{}

type PrivilegedServices struct{}

type PastJudgements struct{}

type ValidatorActivityStatistics struct{}

type AccumulationQueue struct{}

type AccumulationHistory struct{}
