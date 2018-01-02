// Copyright (C) 2018. See AUTHORS.
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

// RandomBytes fills the specified buffer with cryptographically strong random
// bytes using OpenSSL's `RAND_bytes()` function.
func RandomBytes(buffer []byte) error {
	// Don't even attempt to fill empty/nil buffers
	if len(buffer) == 0 {
		return nil
	}

	var bufPtr = (*C.uchar)(&buffer[0])
	var bufLen = C.int(len(buffer))

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if C.RAND_bytes(bufPtr, bufLen) != 1 {
		return errorFromErrorQueue()
	}
	return nil
}

// RandomSeed uses the given data to reseed OpenSSL's random number generator
// using `RAND_seed()`.
// This is equivalent to calling RandomAdd with entropy == len(buffer)
//
// Depending on the RNG implementation, this function may not change the state
// of the generator. An example of this would be hardware RNGs like rdrand.
// No error will be returned in this case.
func RandomSeed(buffer []byte) error {
	if len(buffer) == 0 {
		return errors.New("refusing to seed RNG with empty data")
	}

	var bufPtr = unsafe.Pointer(&buffer[0])
	var bufLen = C.int(len(buffer))

	C.RAND_seed(bufPtr, bufLen)
	return nil
}

// RandomAdd uses the given data to add entropty to OpenSSL's random number
// generator using `RAND_add()`.
// `entropy`` should be the lower bound of the entropy (in bytes) of the data
// contained in `buffer`.
//
// Depending on the RNG implementation, this function may not change the state
// of the generator. An example of this would be hardware RNGs like rdrand.
// No error will be returned in this case.
func RandomAdd(buffer []byte, entropy float64) error {
	if len(buffer) == 0 {
		return errors.New("refusing to seed RNG with empty data")
	}

	var bufPtr = unsafe.Pointer(&buffer[0])
	var bufLen = C.int(len(buffer))

	C.RAND_add(bufPtr, bufLen, C.double(entropy))
	return nil
}
