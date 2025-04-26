package keys

import (
	"crypto/ed25519"

	"github.com/shunsukew/gojam/pkg/crypto/bandersnatch"
	"github.com/shunsukew/gojam/pkg/crypto/bls"
)

// Validator keys tuple. Defined as K;blackboard in the Gray Paper
type ValidatorKey struct {
	BandersnatchPublicKey bandersnatch.PublicKey // kb
	Ed25519PublicKey      ed25519.PublicKey      // ke
	BLSKey                bls.BLSKey             // kbls
	Metadata              [128]byte              // km
}
