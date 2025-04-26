package bandersnatch

// #cgo LDFLAGS: ../../../rust/bandersnatch-ring-vrf/target/release/libbandersnatch_ring_vrf.a -ldl
// #include "../../../rust/bandersnatch-ring-vrf/headers/ringvrf.h"

import "C"

import (
	"unsafe"

	"github.com/pkg/errors"
	"github.com/shunsukew/gojam/pkg/common"
)

func NewRingVerifierCommitment(pubkeys []PublicKey) (RingCommitment, error) {
	var commitment RingCommitment

	if len(pubkeys) != common.NumOfValidators {
		return commitment, errors.New("invalid number of public keys")
	}

	ok := C.new_ring_verifier_commitment(
		(*[PublicKeySize]C.uint8_t)(unsafe.Pointer(&pubkeys[0])),
		C.uint32_t(len(pubkeys)),
		(*C.uint8_t)(unsafe.Pointer(&commitment[0])),
	)
	if !ok {
		return commitment, errors.New("failed to create ring verifier commitment")
	}

	if unsafe.Sizeof(commitment) != RingCommitmentSize {
		return commitment, errors.New("commitment buffer size mismatch")
	}

	return commitment, nil
}
