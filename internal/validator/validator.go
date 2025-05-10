package validator

import (
	"crypto/ed25519"

	"github.com/pkg/errors"
	"github.com/shunsukew/gojam/internal/validator/keys"
	"github.com/shunsukew/gojam/internal/validator/safrole"
	"github.com/shunsukew/gojam/pkg/common"
)

type ValidatorState struct {
	SafroleState       safrole.SafroleState                        // γ
	StagingValidators  *[common.NumOfValidators]*keys.ValidatorKey // ι
	ActiveValidators   *[common.NumOfValidators]*keys.ValidatorKey // κ
	ArchivedValidators *[common.NumOfValidators]*keys.ValidatorKey // λ
}

// Should be invoked when e' > e
func (vs *ValidatorState) RotateValidators(offenders []ed25519.PublicKey) error {
	vs.ArchivedValidators = vs.ActiveValidators
	vs.ActiveValidators = vs.SafroleState.PendingValidators

	newPendingValidators := *vs.StagingValidators // dereference so that not to modify original
	vs.SafroleState.PendingValidators = &newPendingValidators
	vs.nullifyOffenders(offenders)

	err := vs.SafroleState.ComputeRingRoot()
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

// Replace Offenders validator keys with Null before promoting staging keys to pending.
// Check Gray paper equation (6.14)
func (vs *ValidatorState) nullifyOffenders(offenders []ed25519.PublicKey) {
	offendersMap := map[[ed25519.PublicKeySize]byte]struct{}{}
	for _, offender := range offenders {
		offendersMap[[ed25519.PublicKeySize]byte(offender)] = struct{}{}
	}

	for i, validator := range vs.SafroleState.PendingValidators {
		if _, found := offendersMap[[ed25519.PublicKeySize]byte(validator.Ed25519PublicKey)]; found {
			ed25519Pubkey := [ed25519.PublicKeySize]byte{}
			vs.SafroleState.PendingValidators[i] = &keys.ValidatorKey{
				Ed25519PublicKey: ed25519.PublicKey(ed25519Pubkey[:]),
			}
		}
	}
}
