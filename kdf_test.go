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

import (
	"bytes"
	"testing"
)

func TestPBKDF2(t *testing.T) {
	t.Parallel()

	password := []byte("abcdefghijklmnopqrstuvwxyz")
	salt := []byte("sodium chloride")
	iterations := 2000

	perDigestTest := func(nid NID, keySize int, passwd []byte, salt []byte, iterations int) func(t *testing.T) {
		return func(t *testing.T) {
			t.Parallel()

			digest, err := GetDigestByNid(nid)
			if err != nil {
				t.Fatal(err)
			}

			key := make([]byte, keySize)
			err = PBKDF2(passwd, salt, iterations, digest, key)
			if err != nil {
				t.Fatal(err)
			}

			key2 := make([]byte, keySize)
			err = PBKDF2(passwd, salt, iterations, digest, key2)
			if err != nil {
				t.Fatal(err)
			}

			if bytes.Compare(key, key2) != 0 {
				t.Fatal("PBKDF2 with identical inputs produced different keys")
			}
		}
	}

	t.Run("sha1 with 32-byte key", perDigestTest(NID_sha1, 32, password, salt, iterations))
	t.Run("sha1 with 16-byte key", perDigestTest(NID_sha1, 32, password, salt, iterations))
	t.Run("sha256 with 32-byte key", perDigestTest(NID_sha256, 32, password, salt, iterations))
	t.Run("sha256 with 16-byte key", perDigestTest(NID_sha256, 16, password, salt, iterations))
	t.Run("sha512 with 32-byte key", perDigestTest(NID_sha512, 32, password, salt, iterations))
	t.Run("sha512 with 16-byte key", perDigestTest(NID_sha512, 16, password, salt, iterations))

	t.Run("sha256 with 32-byte key, no salt", perDigestTest(NID_sha256, 32, password, nil, iterations))
	t.Run("sha256 with 32-byte key, no password", perDigestTest(NID_sha256, 32, nil, salt, iterations))
	t.Run("sha256 with 32-byte key, no password or salt", perDigestTest(NID_sha256, 32, nil, nil, iterations))
}
