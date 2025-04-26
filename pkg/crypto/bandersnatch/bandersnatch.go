package bandersnatch

const (
	PublicKeySize      = 32
	RingCommitmentSize = 144
)

type PrivateKey [32]byte

type PublicKey [PublicKeySize]byte

type RingCommitment [RingCommitmentSize]byte

type Signature [96]byte

func (sig Signature) Output() VrfOutput {
	// TODO: implement this
	return VrfOutput{}
}

type VrfProof [784]byte

func (proof VrfProof) Output() VrfOutput {
	// TODO: implement this
	return VrfOutput{}
}

type VrfOutput [32]byte
