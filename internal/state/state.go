package jamstate

import (
	"github.com/shunsukew/gojam/internal/accumulate"
	authpool "github.com/shunsukew/gojam/internal/authorizer/pool"
	authqueue "github.com/shunsukew/gojam/internal/authorizer/queue"
	"github.com/shunsukew/gojam/internal/dispute"
	"github.com/shunsukew/gojam/internal/service"
	workreport "github.com/shunsukew/gojam/internal/work/report"

	"github.com/shunsukew/gojam/internal/entropy"
	"github.com/shunsukew/gojam/internal/history"
	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/internal/validator"
)

// σ ≡ (α,β,γ,δ,η,ι,κ,λ,ρ,τ,φ,χ,ψ,π,θ,ξ)
type State struct {
	AuthorizerPools             authpool.AuthorizerPools       // α: The core αuthorizations pool. Equation 8.1 in Gray Paper.
	RecentHistory               history.RecentHistory          // β: Information on the most recent βlocks.
	Services                    service.Services               // δ: The (prior) state of the service accounts.
	EntropyPool                 entropy.EntropyPool            // η: The eηtropy accumulator and epochal raηdomness.
	ValidatorState              validator.ValidatorState       // (ι, κ, λ): The state of the validators related. & γ: State concerning Safrole. Equation 6.3 in Gray Paper.
	PendingWorkReports          workreport.PendingWorkReports  // ρ: The ρending reports, per core, which are being made available prior to accumulation.
	TimeSlot                    jamtime.TimeSlot               // τ: The most recent block’s τimeslot.
	AuthorizerQueues            authqueue.AuthorizerQueues     // φ: The authorization queue.
	PrivilegedServices                                         // χ: The privileged service indices.
	DisputeState                dispute.DisputeState           // ψ: Past judgments/verdicts on work-reports and validators.
	ValidatorActivityStatistics                                // π: The activity statistics for the validators.
	AccumulationQueue           accumulate.AccumulationQueue   // θ: The accumulation queue.
	AccumulationHistory         accumulate.AccumulationHistory // ξ: The accumulation history.
}

type PrivilegedServices struct{}

type ValidatorActivityStatistics struct{}
