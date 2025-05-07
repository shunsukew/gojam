package safrole_validator_test

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	e "github.com/shunsukew/gojam/internal/entropy"
	"github.com/shunsukew/gojam/internal/jamtime"
	"github.com/shunsukew/gojam/internal/validator"
	"github.com/shunsukew/gojam/internal/validator/keys"
	"github.com/shunsukew/gojam/internal/validator/safrole"
	"github.com/shunsukew/gojam/pkg/common"
	"github.com/shunsukew/gojam/pkg/crypto/bandersnatch"
	"github.com/shunsukew/gojam/pkg/crypto/bls"
	"github.com/stretchr/testify/require"
)

func getJsonFilePaths(path string) ([]string, error) {
	var files []string
	err := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(p) == ".json" {
			files = append(files, p)
		}
		return nil
	})
	return files, err
}

func hexToEd25519PublicKey(hex string) ed25519.PublicKey {
	return ed25519.PublicKey(common.FromHex(hex))
}

func TestSafroleAndValidatorStateTransition(t *testing.T) {
	t.Run(testSpec, func(t *testing.T) {
		filePaths, err := getJsonFilePaths(vectorFolderPath)
		if err != nil {
			require.NoError(t, err, "failed to get JSON file paths")
		}

		for _, filePath := range filePaths {
			testCase := fmt.Sprintf("Test %s", filepath.Base(filePath))
			t.Run(testCase, func(t *testing.T) {
				file, err := os.ReadFile(filePath)
				if err != nil {
					require.NoErrorf(t, err, "failed to read test vector file: %s", filePath)
				}

				var testVector TestVector
				err = json.Unmarshal(file, &testVector)
				if err != nil {
					require.NoError(t, err, "failed to unmarshal test vector: %s", filePath)
				}

				// Prepare inputs of state transition function
				currentTimeSlot := testVector.Input.Slot
				prevTimeSlot := testVector.PreState.Tau
				entropy := bandersnatch.VrfOutput(testVector.Input.Entropy)
				entropyPool := e.EntropyPool{}
				for i := range len(entropyPool) {
					entropyPool[i] = testVector.PreState.Eta[i]
				}
				tickets := make([]safrole.TicketProof, len(testVector.Input.Extrinsic))
				for i, extrinsic := range testVector.Input.Extrinsic {
					tickets[i] = safrole.TicketProof{
						TicketProof: extrinsic.Signature,
						EntryIndex:  extrinsic.Attempt,
					}
				}

				validatorState, err := toValidatorState(testVector.PreState)
				if err != nil {
					require.NoError(t, err, "failed to create validator state")
				}

				expectedValidatorState, err := toValidatorState(testVector.PostState)
				if err != nil {
					require.NoError(t, err, "failed to create expected validator state")
				}

				_, _, _, err = validatorState.Update(currentTimeSlot, prevTimeSlot, entropy, entropyPool, tickets, []ed25519.PublicKey{})

				// Safrole state check
				require.Equal(t, validatorState.SafroleState.PendingValidators, expectedValidatorState.SafroleState.PendingValidators)
				// require.Equal(t, validatorState.SafroleState.EpochRoot, expectedValidatorState.SafroleState.EpochRoot)
				// require.Equal(t, validatorState.SafroleState.SealingKeySeries, expectedValidatorState.SafroleState.SealingKeySeries)
				// require.Equal(t, validatorState.SafroleState.TicketsAccumulator, expectedValidatorState.SafroleState.TicketsAccumulator)

				// Validator state check
				require.Equal(t, validatorState.StagingValidators, expectedValidatorState.StagingValidators)
				require.Equal(t, validatorState.ActiveValidators, expectedValidatorState.ActiveValidators)
				require.Equal(t, validatorState.ArchivedValidators, expectedValidatorState.ArchivedValidators)

				// require.Equal(t, validatorState, expectedValidatorState)
			})
		}
	})
}

func toValidatorState(
	preState State,
) (*validator.ValidatorState, error) {
	pendingValidators := [common.NumOfValidators]keys.ValidatorKey{}
	for i, validator := range preState.GammaK {
		pendingValidators[i] = keys.ValidatorKey{
			BandersnatchPublicKey: validator.Bandersnatch,
			Ed25519PublicKey:      hexToEd25519PublicKey(validator.Ed25519),
			BLSKey:                validator.Bls,
			Metadata:              [keys.ValidatorKeyMetadataSize]byte(common.FromHex(validator.Metadata)),
		}
	}
	stagingValidators := [common.NumOfValidators]keys.ValidatorKey{}
	for i, validator := range preState.Iota {
		stagingValidators[i] = keys.ValidatorKey{
			BandersnatchPublicKey: validator.Bandersnatch,
			Ed25519PublicKey:      hexToEd25519PublicKey(validator.Ed25519),
			BLSKey:                validator.Bls,
			Metadata:              [keys.ValidatorKeyMetadataSize]byte(common.FromHex(validator.Metadata)),
		}
	}
	activeValidators := [common.NumOfValidators]keys.ValidatorKey{}
	for i, validator := range preState.Kappa {
		activeValidators[i] = keys.ValidatorKey{
			BandersnatchPublicKey: validator.Bandersnatch,
			Ed25519PublicKey:      hexToEd25519PublicKey(validator.Ed25519),
			BLSKey:                validator.Bls,
			Metadata:              [keys.ValidatorKeyMetadataSize]byte(common.FromHex(validator.Metadata)),
		}
	}
	archivedValidators := [common.NumOfValidators]keys.ValidatorKey{}
	for i, validator := range preState.Lambda {
		archivedValidators[i] = keys.ValidatorKey{
			BandersnatchPublicKey: validator.Bandersnatch,
			Ed25519PublicKey:      hexToEd25519PublicKey(validator.Ed25519),
			BLSKey:                validator.Bls,
			Metadata:              [keys.ValidatorKeyMetadataSize]byte(common.FromHex(validator.Metadata)),
		}
	}

	// sealing key series
	var sealingKeySeries safrole.SealingKeySeriesKind
	if len(preState.GammaS.Tickets) != 0 {
		tickets := make([]safrole.Ticket, len(preState.GammaS.Tickets))
		for i, ticket := range preState.GammaS.Tickets {
			tickets[i] = safrole.Ticket{
				TicketID:   ticket.ID,
				EntryIndex: ticket.Attempt,
			}
		}
		sealingKeySeries = safrole.Tickets(tickets)
	} else {
		// fallback mode
		fallbackKeys := safrole.FallbackKeys{}
		for i, key := range preState.GammaS.Keys {
			fallbackKeys[i] = bandersnatch.PublicKey(common.FromHex(key))
		}
		sealingKeySeries = fallbackKeys
	}

	ticketAccumulator := make([]safrole.Ticket, len(preState.GammaA))
	for i, ticket := range preState.GammaA {
		ticketAccumulator[i] = safrole.Ticket{
			TicketID:   ticket.ID,
			EntryIndex: ticket.Attempt,
		}
	}

	safroleState := &safrole.SafroleState{
		PendingValidators:  &pendingValidators,
		EpochRoot:          preState.GammaZ,
		SealingKeySeries:   sealingKeySeries,
		TicketsAccumulator: ticketAccumulator,
	}

	return &validator.ValidatorState{
		SafroleState:       *safroleState,
		StagingValidators:  &stagingValidators,
		ActiveValidators:   &activeValidators,
		ArchivedValidators: &archivedValidators,
	}, nil
}

type TestVector struct {
	Input     Input  `json:"input"`
	PreState  State  `json:"pre_state"`
	PostState State  `json:"post_state"`
	Output    Output `json:"output"`
}

type Input struct {
	Slot      jamtime.TimeSlot `json:"slot"`
	Entropy   common.Hash      `json:"entropy"`
	Extrinsic []Extrinsic      `json:"extrinsic"`
}

type Extrinsic struct {
	Attempt   uint8                  `json:"attempt"`
	Signature bandersnatch.Signature `json:"signature"`
}

type State struct {
	Tau    jamtime.TimeSlot            `json:"tau"`
	Eta    []common.Hash               `json:"eta"`
	Lambda []ValidatorKey              `json:"lambda"`
	Kappa  []ValidatorKey              `json:"kappa"`
	GammaK []ValidatorKey              `json:"gamma_k"`
	Iota   []ValidatorKey              `json:"iota"`
	GammaA []Ticket                    `json:"gamma_a"`
	GammaS SealingKeySeries            `json:"gamma_s"`
	GammaZ bandersnatch.RingCommitment `json:"gamma_z"`
}

type ValidatorKey struct {
	Bandersnatch bandersnatch.PublicKey `json:"bandersnatch"`
	Ed25519      string                 `json:"ed25519"`
	Bls          bls.BLSKey             `json:"bls"`
	Metadata     string                 `json:"metadata"`
}

type Ticket struct {
	ID      bandersnatch.VrfOutput `json:"id"`
	Attempt uint8                  `json:"attempt"`
}

type SealingKeySeries struct {
	Tickets []Ticket `json:"tickets"`
	Keys    []string `json:"keys"`
}

type Output struct {
	Ok  Ok     `json:"ok"`
	Err string `json:"err"`
}

type Ok struct {
	EpochMark   EpochMarker `json:"epoch_mark"`
	TicketsMark []Ticket    `json:"tickets_mark"`
}

type EpochMarker struct {
	Entropy    common.Hash              `json:"entropy"`
	Validators []bandersnatch.PublicKey `json:"validators"`
}
