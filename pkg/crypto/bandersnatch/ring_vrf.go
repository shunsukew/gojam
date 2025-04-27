//go:build cgo

package bandersnatch

// #cgo pkg-config: bandersnatch-ring-vrf
// #include <stddef.h>
// #include "bandersnatch-ring-vrf.h"
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/pkg/errors"
)

func newSecretFromSeed(seed []byte) (PrivateKey, error) {
	var secret PrivateKey

	ok := C.new_secret_from_seed(
		(*C.uchar)(unsafe.Pointer(&seed[0])),
		C.size_t(len(seed)),
		(*C.uchar)(unsafe.Pointer(&secret[0])),
	)

	fmt.Println("HERE")
	fmt.Println(ok)

	if !ok {
		return secret, errors.New("failed to create secret from seed")
	}

	if unsafe.Sizeof(secret) != PrivateKeySize {
		return secret, errors.New("secret buffer size mismatch")
	}

	return secret, nil
}

func newPublicKeyFromSecret(secret PrivateKey) (PublicKey, error) {
	var publicKey PublicKey

	ok := C.new_public_key_from_secret(
		(*C.uchar)(unsafe.Pointer(&secret[0])),
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
	)
	if !ok {
		return publicKey, errors.New("failed to create public key from secret")
	}

	if unsafe.Sizeof(publicKey) != PublicKeySize {
		return publicKey, errors.New("public key buffer size mismatch")
	}

	return publicKey, nil
}

func newRingCommitment(ringPubkeys []PublicKey) (RingCommitment, error) {
	var commitment RingCommitment

	ok := C.new_ring_commitment(
		(*[PublicKeySize]C.uchar)(unsafe.Pointer(&ringPubkeys[0])),
		C.size_t(len(ringPubkeys)),
		(*C.uchar)(unsafe.Pointer(&commitment[0])),
	)
	if !ok {
		return commitment, errors.New("failed to create ring verifier commitment")
	}

	if unsafe.Sizeof(commitment) != RingCommitmentSize {
		return commitment, errors.New("commitment buffer size mismatch")
	}

	return commitment, nil
}

func sign(
	ringPubkeys []PublicKey,
	proverIndex uint8,
	proverSecret PrivateKey,
	input []byte,
	auxData []byte,
) (Signature, error) {
	var signature Signature

	ok := C.ring_vrf_sign(
		(*[PublicKeySize]C.uchar)(unsafe.Pointer(&ringPubkeys[0])),
		C.size_t(len(ringPubkeys)),
		(*C.uchar)(unsafe.Pointer(&proverIndex)),
		(*C.uchar)(unsafe.Pointer(&proverSecret[0])),
		(*C.uchar)(unsafe.Pointer(&input[0])),
		C.size_t(len(input)),
		(*C.uchar)(unsafe.Pointer(&auxData[0])),
		C.size_t(len(auxData)),
		(*C.uchar)(unsafe.Pointer(&signature[0])),
	)
	if !ok {
		return signature, errors.New("failed to sign ring vrf")
	}

	if unsafe.Sizeof(signature) != SignatureSize {
		return signature, errors.New("signature buffer size mismatch")
	}

	return signature, nil
}

func verify(
	input []byte,
	auxData []byte,
	commitment RingCommitment,
	ringProof Signature,
) (VrfOutput, error) {
	var output VrfOutput

	ok := C.ring_vrf_verify(
		(*C.uchar)(unsafe.Pointer(&input[0])),
		C.size_t(len(input)),
		(*C.uchar)(unsafe.Pointer(&auxData[0])),
		C.size_t(len(auxData)),
		(*C.uchar)(unsafe.Pointer(&commitment[0])),
		(*C.uchar)(unsafe.Pointer(&ringProof[0])),
		(*C.uchar)(unsafe.Pointer(&output[0])),
	)
	if !ok {
		return output, errors.New("failed to verify ring vrf")
	}

	if unsafe.Sizeof(output) != VrfOutputSize {
		return output, errors.New("output buffer size mismatch")
	}

	return output, nil
}
