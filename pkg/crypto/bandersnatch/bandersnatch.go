package bandersnatch

type PrivateKey [32]byte

type PublicKey [32]byte

type RingRoot [144]byte

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
