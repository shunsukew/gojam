package bandersnatch

import (
	"fmt"
	"testing"
)

func TestRingVRFSignAndVerify(t *testing.T) {
	ringPubkeys := make([]PublicKey, 3)
	proverIndex := 0
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

	fmt.Println(input)
	fmt.Println(auxData)
	fmt.Println(commitment)

	// Sign the input
	// signature, err := sign(ringPubkeys, proverIndex, proverSecret, input, auxData)
	// if err != nil {
	// t.Fatalf("failed to sign: %v", err)
	// }

	// // Verify the signature
	// output, err := verify(input, auxData, commitment, signature)
	// if err != nil {
	// t.Fatal("signature verification failed")
	// }
}
