package validator

import (
	"github.com/shunsukew/gojam/internal/validator/keys"
	"github.com/shunsukew/gojam/internal/validator/safrole"
	"github.com/shunsukew/gojam/pkg/common"
)

type ValidatorState struct {
	StagingValidators  [common.NumOfValidators]keys.ValidatorKey // ι
	ActiveValidators   [common.NumOfValidators]keys.ValidatorKey // κ
	ArchivedValidators [common.NumOfValidators]keys.ValidatorKey // λ
	SafroleState       safrole.SafroleState                      // γ
}

// Should be invoked when e' > e
func (vs *ValidatorState) RotateValidators() {
	vs.ArchivedValidators = vs.ActiveValidators
	vs.ActiveValidators = vs.SafroleState.PendingValidators

	// TODO: Calculate bandersnatch root

	// TODO: Replace Offenders keys with Null before promoting staging keys to pending.
	// Check equation (6.14)
	vs.SafroleState.PendingValidators = vs.StagingValidators
}
