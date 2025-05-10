package safrole_validator_test

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/shunsukew/gojam/internal/block"
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
				offenders := make([]ed25519.PublicKey, len(testVector.PreState.PostOffenders))
				for i, offender := range testVector.PreState.PostOffenders {
					offenders[i] = hexToEd25519PublicKey(offender)
				}

				validatorState, err := toValidatorState(testVector.PreState)
				if err != nil {
					require.NoError(t, err, "failed to create validator state")
				}

				expectedValidatorState, err := toValidatorState(testVector.PostState)
				if err != nil {
					require.NoError(t, err, "failed to create expected validator state")
				}

				expectedOutput := testVector.Output
				var expectedEpochMarker *block.EpochMarker
				if expectedOutput.Ok.EpochMark != nil {
					bandersnatchKeys := [common.NumOfValidators]bandersnatch.PublicKey{}
					for i, validator := range expectedOutput.Ok.EpochMark.Validators {
						bandersnatchKeys[i] = bandersnatch.PublicKey(common.FromHex(validator.Bandersnatch))
					}
					expectedEpochMarker = &block.EpochMarker{
						Entropies: struct {
							Next    common.Hash
							Current common.Hash
						}{
							Next:    expectedOutput.Ok.EpochMark.Entropy,
							Current: expectedOutput.Ok.EpochMark.TicketEntropy,
						},
						BandersnatchPubKeys: bandersnatchKeys,
					}
				}

				var expectedWinningTicketMarker *block.WinningTicketMarker
				if expectedOutput.Ok.TicketsMark != nil {
					tickets := make([]safrole.Ticket, len(expectedOutput.Ok.TicketsMark))
					for i, ticket := range expectedOutput.Ok.TicketsMark {
						tickets[i] = safrole.Ticket{
							TicketID:   ticket.ID,
							EntryIndex: ticket.Attempt,
						}
					}
					expectedWinningTicketMarker = &block.WinningTicketMarker{
						Tickets: safrole.Tickets(tickets),
					}
				}

				_, epochMarker, winningTicketMarker, err := validatorState.Update(currentTimeSlot, prevTimeSlot, entropy, entropyPool, tickets, offenders)
				if expectedOutput.Err != "" {
					require.Error(t, err, "error expected: %v", err)
				} else {
					require.NoError(t, err, "error unexpected: %s", err)
				}

				// Safrole state check
				require.Equal(t, expectedValidatorState.SafroleState.PendingValidators, validatorState.SafroleState.PendingValidators)
				require.Equal(t, expectedValidatorState.SafroleState.EpochRoot, validatorState.SafroleState.EpochRoot)
				require.Equal(t, expectedValidatorState.SafroleState.SealingKeySeries, validatorState.SafroleState.SealingKeySeries)
				require.Equal(t, expectedValidatorState.SafroleState.TicketsAccumulator, validatorState.SafroleState.TicketsAccumulator)

				// Validator state check
				require.Equal(t, expectedValidatorState.StagingValidators, validatorState.StagingValidators)
				require.Equal(t, expectedValidatorState.ActiveValidators, validatorState.ActiveValidators)
				require.Equal(t, expectedValidatorState.ArchivedValidators, validatorState.ArchivedValidators)

				// Entire state check
				require.Equal(t, validatorState, expectedValidatorState)

				// Epoch marker check
				require.Equal(t, expectedEpochMarker, epochMarker)

				// Winning ticket marker check
				require.Equal(t, expectedWinningTicketMarker, winningTicketMarker)
			})
		}
	})
}

func toValidatorState(
	state State,
) (*validator.ValidatorState, error) {
	pendingValidators := [common.NumOfValidators]keys.ValidatorKey{}
	for i, validator := range state.GammaK {
		pendingValidators[i] = keys.ValidatorKey{
			BandersnatchPublicKey: validator.Bandersnatch,
			Ed25519PublicKey:      hexToEd25519PublicKey(validator.Ed25519),
			BLSKey:                validator.Bls,
			Metadata:              [keys.ValidatorKeyMetadataSize]byte(common.FromHex(validator.Metadata)),
		}
	}
	stagingValidators := [common.NumOfValidators]keys.ValidatorKey{}
	for i, validator := range state.Iota {
		stagingValidators[i] = keys.ValidatorKey{
			BandersnatchPublicKey: validator.Bandersnatch,
			Ed25519PublicKey:      hexToEd25519PublicKey(validator.Ed25519),
			BLSKey:                validator.Bls,
			Metadata:              [keys.ValidatorKeyMetadataSize]byte(common.FromHex(validator.Metadata)),
		}
	}
	activeValidators := [common.NumOfValidators]keys.ValidatorKey{}
	for i, validator := range state.Kappa {
		activeValidators[i] = keys.ValidatorKey{
			BandersnatchPublicKey: validator.Bandersnatch,
			Ed25519PublicKey:      hexToEd25519PublicKey(validator.Ed25519),
			BLSKey:                validator.Bls,
			Metadata:              [keys.ValidatorKeyMetadataSize]byte(common.FromHex(validator.Metadata)),
		}
	}
	archivedValidators := [common.NumOfValidators]keys.ValidatorKey{}
	for i, validator := range state.Lambda {
		archivedValidators[i] = keys.ValidatorKey{
			BandersnatchPublicKey: validator.Bandersnatch,
			Ed25519PublicKey:      hexToEd25519PublicKey(validator.Ed25519),
			BLSKey:                validator.Bls,
			Metadata:              [keys.ValidatorKeyMetadataSize]byte(common.FromHex(validator.Metadata)),
		}
	}

	// sealing key series
	var sealingKeySeries safrole.SealingKeySeriesKind
	if len(state.GammaS.Tickets) != 0 {
		tickets := make([]safrole.Ticket, len(state.GammaS.Tickets))
		for i, ticket := range state.GammaS.Tickets {
			tickets[i] = safrole.Ticket{
				TicketID:   ticket.ID,
				EntryIndex: ticket.Attempt,
			}
		}
		sealingKeySeries = safrole.Tickets(tickets)
	} else {
		// fallback mode
		fallbackKeys := safrole.FallbackKeys{}
		for i, key := range state.GammaS.Keys {
			fallbackKeys[i] = bandersnatch.PublicKey(common.FromHex(key))
		}
		sealingKeySeries = fallbackKeys
	}

	ticketAccumulator := make([]safrole.Ticket, len(state.GammaA))
	for i, ticket := range state.GammaA {
		ticketAccumulator[i] = safrole.Ticket{
			TicketID:   ticket.ID,
			EntryIndex: ticket.Attempt,
		}
	}

	safroleState := &safrole.SafroleState{
		PendingValidators:  &pendingValidators,
		EpochRoot:          state.GammaZ,
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
	Tau           jamtime.TimeSlot            `json:"tau"`
	Eta           []common.Hash               `json:"eta"`
	Lambda        []ValidatorKey              `json:"lambda"`
	Kappa         []ValidatorKey              `json:"kappa"`
	GammaK        []ValidatorKey              `json:"gamma_k"`
	Iota          []ValidatorKey              `json:"iota"`
	GammaA        []Ticket                    `json:"gamma_a"`
	GammaS        SealingKeySeries            `json:"gamma_s"`
	GammaZ        bandersnatch.RingCommitment `json:"gamma_z"`
	PostOffenders []string                    `json:"post_offenders"`
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
	EpochMark   *EpochMarker `json:"epoch_mark"`
	TicketsMark []Ticket     `json:"tickets_mark"`
}

type EpochMarker struct {
	Entropy       common.Hash            `json:"entropy"`
	TicketEntropy common.Hash            `json:"tickets_entropy"`
	Validators    []EpochMarkerValidator `json:"validators"`
}

type EpochMarkerValidator struct {
	Bandersnatch string `json:"bandersnatch"`
	Ed25519      string `json:"ed25519"`
}
