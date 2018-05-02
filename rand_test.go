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

import (
	"testing"
)

func TestRandBytes(t *testing.T) {
	t.Parallel()

	t.Run("empty buffer", func(t *testing.T) {
		t.Parallel()
		err := RandomBytes(nil)
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("16-byte buffer", func(t *testing.T) {
		t.Parallel()
		buff := make([]byte, 16, 16)
		err := RandomBytes(buff)
		if err != nil {
			t.Fatal(err)
		}
		// Check that there was actually some data stored in buff
		// If the RNG is working correctly, this will technically fail once in
		// every 2**128 runs, which I consider a significantly insignificant chance.
		var numNonzero int
		for _, value := range buff {
			if value != 0 {
				numNonzero++
			}
		}
		if numNonzero == 0 {
			t.Fatal("buffer contains only zero bytes")
		}
	})
}
