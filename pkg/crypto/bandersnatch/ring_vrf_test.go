package bandersnatch

import (
	"fmt"
	"testing"
)

func TestRingVRFSignAndVerify(t *testing.T) {
	ringPubkeys := make([]PublicKey, 3)
	proverIndex := uint8(0)
	proverSecret, err := newSecretFromSeed([]byte("prover secret"))
	if err != nil {
		fmt.Println(err)
		t.Fatalf("failed to create prover secret: %v", err)
	}
	proverPubkey, err := newPublicKeyFromSecret(proverSecret)
	if err != nil {
		t.Fatalf("failed to create prover public key: %v", err)
	}
	ringPubkeys[proverIndex] = proverPubkey

	input := []byte("input data")
	auxData := []byte("aux data")

	commitment, err := newRingCommitment(ringPubkeys)
	if err != nil {
		t.Fatalf("failed to create ring commitment: %v", err)
	}

	signature, err := sign(ringPubkeys, proverIndex, proverSecret, input, auxData)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	_, err = verify(input, auxData, commitment, signature)
	if err != nil {
		t.Fatal("signature verification failed")
	}
}

// Test auxiliary data doesn't affect the output
func TestRingVRFOutputs(t *testing.T) {
	ringPubkeys := make([]PublicKey, 3)
	proverIndex := uint8(0)
	proverSecret, err := newSecretFromSeed([]byte("prover secret"))
	if err != nil {
		t.Fatalf("failed to create prover secret: %v", err)
	}
	proverPubkey, err := newPublicKeyFromSecret(proverSecret)
	if err != nil {
		t.Fatalf("failed to create prover public key: %v", err)
	}
	ringPubkeys[proverIndex] = proverPubkey

	input := []byte("input data")
	auxData1 := []byte("aux data 1")
	auxData2 := []byte("aux data 2")

	commitment, err := newRingCommitment(ringPubkeys)
	if err != nil {
		t.Fatalf("failed to create ring commitment: %v", err)
	}

	signature1, err := sign(ringPubkeys, proverIndex, proverSecret, input, auxData1)
	if err != nil {
		t.Fatalf("failed to sign with auxData1: %v", err)
	}

	signature2, err := sign(ringPubkeys, proverIndex, proverSecret, input, auxData2)
	if err != nil {
		t.Fatalf("failed to sign with auxData2: %v", err)
	}

	// Verify the signatures
	output1, err := verify(input, auxData1, commitment, signature1)
	if err != nil {
		t.Fatal("signature verification with auxData1 failed")
	}

	output2, err := verify(input, auxData2, commitment, signature2)
	if err != nil {
		t.Fatal("signature verification with auxData2 failed")
	}

	if output1 != output2 {
		t.Fatal("outputs should be same for different auxData")
	}
}
