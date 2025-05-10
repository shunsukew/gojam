package keys

import (
	"crypto/ed25519"

	"github.com/shunsukew/gojam/pkg/crypto/bandersnatch"
	"github.com/shunsukew/gojam/pkg/crypto/bls"
)

const (
	ValidatorKeyMetadataSize = 128
)

// Validator keys tuple. Defined as K;blackboard in the Gray Paper
type ValidatorKey struct {
	BandersnatchPublicKey bandersnatch.PublicKey         // kb
	Ed25519PublicKey      ed25519.PublicKey              // ke
	BLSKey                bls.BLSKey                     // kbls
	Metadata              [ValidatorKeyMetadataSize]byte // km
}
