package bandersnatch

type PrivateKey [32]byte

type PublicKey [32]byte

func (pk PublicKey) SealingKeyKind() {}

type Signature [96]byte

type OutputHash [32]byte

type RingRoot [144]byte
