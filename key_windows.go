package openssl

// #include "shim.h"
// #include <openssl/rsa.h>
// #include <openssl/pem.h>
import "C"

import (
	"runtime"
)

// GenerateRSAKeyWithExponent generates a new RSA private key.
// GenerateRSAKeyWithExponent generates a new RSA private key.
func GenerateRSAKeyWithExponent(bits int) (PrivateKey, error) {
	key := C.evp_rsa_gen(C.int(bits))
	p := &pKey{key: key}
	runtime.SetFinalizer(p, freePKey)
	return p, nil
}
