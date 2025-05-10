package validator

import (
	"crypto/ed25519"
	"crypto/rand"
	mathrand "math/rand"
	"testing"

	"github.com/shunsukew/gojam/internal/validator/keys"
	"github.com/shunsukew/gojam/internal/validator/safrole"
	"github.com/shunsukew/gojam/pkg/common"
	"github.com/stretchr/testify/require"
)

func generateDummyKey() ed25519.PublicKey {
	seed := make([]byte, ed25519.SeedSize)
	_, err := rand.Read(seed)
	if err != nil {
		panic("failed to generate random seed: " + err.Error())
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey)
}

func TestNullifyOffenders(t *testing.T) {
	// Setup initial pending validators
	pubKeys := make([]ed25519.PublicKey, common.NumOfValidators)
	pendingValidators := &[common.NumOfValidators]*keys.ValidatorKey{}

	for i := range common.NumOfValidators {
		pubKey := generateDummyKey()
		pubKeys[i] = pubKey
		pendingValidators[i] = &keys.ValidatorKey{Ed25519PublicKey: pubKey}
	}

	vs := &ValidatorState{
		SafroleState: &safrole.SafroleState{
			PendingValidators: pendingValidators,
		},
	}

	offenderCount := mathrand.Intn(3) + 1
	offenderIndices := map[int]struct{}{}
	for len(offenderIndices) < offenderCount {
		offenderIndices[mathrand.Intn(common.NumOfValidators)] = struct{}{}
	}
	offenders := []ed25519.PublicKey{}
	for idx := range offenderIndices {
		offenders = append(offenders, pubKeys[idx])
	}

	prevValidatorState := vs
	vs.nullifyOffenders(offenders)

	for i, v := range vs.SafroleState.PendingValidators {
		_, isOffender := offenderIndices[i]
		if isOffender {
			require.Equal(t, ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)), v.Ed25519PublicKey, "Offender key should be nullified")
		} else {
			require.Equal(t, prevValidatorState.SafroleState.PendingValidators[i].Ed25519PublicKey, v.Ed25519PublicKey, "Non-offender key should remain unchanged")
		}
	}
}
