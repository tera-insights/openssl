// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openssl

// #include "shim.h"
// #include <stdlib.h>
import "C"
import (
	"errors"
	"runtime"
	"unsafe"
)

// PBKDF2 derives a key from a password using a salt and iteration count as
// specified in RFC 2898.
//
// The result of the key derivation is stored in `dest`, which must be a slice
// of the desired size.
func PBKDF2(pass []byte, salt []byte, iterations int, digest *Digest, dest []byte) error {
	if dest == nil {
		return errors.New("no output slice specified")
	}
	if len(dest) < 1 {
		return errors.New("output slice must have length > 0")
	}
	if digest == nil {
		return errors.New("no digest specified")
	}

	var passBytes *C.char
	if pass != nil {
		passBytes = (*C.char)(unsafe.Pointer(&pass[0]))
	}

	var saltBytes *C.uchar
	if salt != nil {
		saltBytes = (*C.uchar)(&salt[0])
	}

	destBytes := (*C.uchar)(&dest[0])

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	rc := C.PKCS5_PBKDF2_HMAC(
		passBytes,
		C.int(len(pass)),
		saltBytes,
		C.int(len(salt)),
		C.int(iterations),
		digest.ptr,
		C.int(len(dest)),
		destBytes,
	)
	if rc != 1 {
		return errorFromErrorQueue()
	}

	return nil
}
