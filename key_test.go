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
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	pem_pkg "encoding/pem"
	"io/ioutil"
	"testing"
)

func TestMarshal(t *testing.T) {
	key, err := LoadPrivateKeyFromPEM(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := LoadCertificateFromPEM(certBytes)
	if err != nil {
		t.Fatal(err)
	}

	privateBlock, _ := pem_pkg.Decode(keyBytes)
	key, err = LoadPrivateKeyFromDER(privateBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	pem, err := cert.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pem, certBytes) {
		ioutil.WriteFile("generated", pem, 0644)
		ioutil.WriteFile("hardcoded", certBytes, 0644)
		t.Fatal("invalid cert pem bytes")
	}

	pem, err = key.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pem, keyBytes) {
		ioutil.WriteFile("generated", pem, 0644)
		ioutil.WriteFile("hardcoded", keyBytes, 0644)
		t.Fatal("invalid private key pem bytes")
	}
	tls_cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	tls_key, ok := tls_cert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("FASDFASDF")
	}
	_ = tls_key

	der, err := key.MarshalPKCS1PrivateKeyDER()
	if err != nil {
		t.Fatal(err)
	}
	tls_der := x509.MarshalPKCS1PrivateKey(tls_key)
	if !bytes.Equal(der, tls_der) {
		t.Fatalf("invalid private key der bytes: %s\n v.s. %s\n",
			hex.Dump(der), hex.Dump(tls_der))
	}

	der, err = key.MarshalPKIXPublicKeyDER()
	if err != nil {
		t.Fatal(err)
	}
	tls_der, err = x509.MarshalPKIXPublicKey(&tls_key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(der, tls_der) {
		ioutil.WriteFile("generated", []byte(hex.Dump(der)), 0644)
		ioutil.WriteFile("hardcoded", []byte(hex.Dump(tls_der)), 0644)
		t.Fatal("invalid public key der bytes")
	}

	pem, err = key.MarshalPKIXPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	tls_pem := pem_pkg.EncodeToMemory(&pem_pkg.Block{
		Type: "PUBLIC KEY", Bytes: tls_der})
	if !bytes.Equal(pem, tls_pem) {
		ioutil.WriteFile("generated", pem, 0644)
		ioutil.WriteFile("hardcoded", tls_pem, 0644)
		t.Fatal("invalid public key pem bytes")
	}

	loaded_pubkey_from_pem, err := LoadPublicKeyFromPEM(pem)
	if err != nil {
		t.Fatal(err)
	}

	loaded_pubkey_from_der, err := LoadPublicKeyFromDER(der)
	if err != nil {
		t.Fatal(err)
	}

	new_der_from_pem, err := loaded_pubkey_from_pem.MarshalPKIXPublicKeyDER()
	if err != nil {
		t.Fatal(err)
	}

	new_der_from_der, err := loaded_pubkey_from_der.MarshalPKIXPublicKeyDER()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(new_der_from_der, tls_der) {
		ioutil.WriteFile("generated", []byte(hex.Dump(new_der_from_der)), 0644)
		ioutil.WriteFile("hardcoded", []byte(hex.Dump(tls_der)), 0644)
		t.Fatal("invalid public key der bytes")
	}

	if !bytes.Equal(new_der_from_pem, tls_der) {
		ioutil.WriteFile("generated", []byte(hex.Dump(new_der_from_pem)), 0644)
		ioutil.WriteFile("hardcoded", []byte(hex.Dump(tls_der)), 0644)
		t.Fatal("invalid public key der bytes")
	}
}

func TestGenerate(t *testing.T) {
	key, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	_, err = key.MarshalPKIXPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	_, err = key.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	_, err = GenerateRSAKeyWithExponent(1024, 65537)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGenerateEC(t *testing.T) {
	key, err := GenerateECKey(Prime256v1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = key.MarshalPKIXPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	_, err = key.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
}

func TestSign(t *testing.T) {
	key, _ := GenerateRSAKey(1024)
	data := []byte("the quick brown fox jumps over the lazy dog")
	_, err := key.SignPKCS1v15(SHA1_Method, data)
	if err != nil {
		t.Fatal(err)
	}
	_, err = key.SignPKCS1v15(SHA256_Method, data)
	if err != nil {
		t.Fatal(err)
	}
	_, err = key.SignPKCS1v15(SHA512_Method, data)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSignEC(t *testing.T) {
	t.Parallel()

	key, err := GenerateECKey(Prime256v1)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("the quick brown fox jumps over the lazy dog")

	t.Run("sha1", func(t *testing.T) {
		t.Parallel()
		sig, err := key.SignPKCS1v15(SHA1_Method, data)
		if err != nil {
			t.Fatal(err)
		}
		err = key.VerifyPKCS1v15(SHA1_Method, data, sig)
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("sha256", func(t *testing.T) {
		t.Parallel()
		sig, err := key.SignPKCS1v15(SHA256_Method, data)
		if err != nil {
			t.Fatal(err)
		}
		err = key.VerifyPKCS1v15(SHA256_Method, data, sig)
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("sha512", func(t *testing.T) {
		t.Parallel()
		sig, err := key.SignPKCS1v15(SHA512_Method, data)
		if err != nil {
			t.Fatal(err)
		}
		err = key.VerifyPKCS1v15(SHA512_Method, data, sig)
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestMarshalEC(t *testing.T) {
	key, err := LoadPrivateKeyFromPEM(prime256v1KeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := LoadCertificateFromPEM(prime256v1CertBytes)
	if err != nil {
		t.Fatal(err)
	}

	privateBlock, _ := pem_pkg.Decode(prime256v1KeyBytes)
	key, err = LoadPrivateKeyFromDER(privateBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	pem, err := cert.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pem, prime256v1CertBytes) {
		ioutil.WriteFile("generated", pem, 0644)
		ioutil.WriteFile("hardcoded", prime256v1CertBytes, 0644)
		t.Fatal("invalid cert pem bytes")
	}

	pem, err = key.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pem, prime256v1KeyBytes) {
		ioutil.WriteFile("generated", pem, 0644)
		ioutil.WriteFile("hardcoded", prime256v1KeyBytes, 0644)
		t.Fatal("invalid private key pem bytes")
	}
	tls_cert, err := tls.X509KeyPair(prime256v1CertBytes, prime256v1KeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	tls_key, ok := tls_cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("FASDFASDF")
	}
	_ = tls_key

	der, err := key.MarshalPKCS1PrivateKeyDER()
	if err != nil {
		t.Fatal(err)
	}
	tls_der, err := x509.MarshalECPrivateKey(tls_key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(der, tls_der) {
		t.Fatalf("invalid private key der bytes: %s\n v.s. %s\n",
			hex.Dump(der), hex.Dump(tls_der))
	}

	der, err = key.MarshalPKIXPublicKeyDER()
	if err != nil {
		t.Fatal(err)
	}
	tls_der, err = x509.MarshalPKIXPublicKey(&tls_key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(der, tls_der) {
		ioutil.WriteFile("generated", []byte(hex.Dump(der)), 0644)
		ioutil.WriteFile("hardcoded", []byte(hex.Dump(tls_der)), 0644)
		t.Fatal("invalid public key der bytes")
	}

	pem, err = key.MarshalPKIXPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	tls_pem := pem_pkg.EncodeToMemory(&pem_pkg.Block{
		Type: "PUBLIC KEY", Bytes: tls_der})
	if !bytes.Equal(pem, tls_pem) {
		ioutil.WriteFile("generated", pem, 0644)
		ioutil.WriteFile("hardcoded", tls_pem, 0644)
		t.Fatal("invalid public key pem bytes")
	}

	loaded_pubkey_from_pem, err := LoadPublicKeyFromPEM(pem)
	if err != nil {
		t.Fatal(err)
	}

	loaded_pubkey_from_der, err := LoadPublicKeyFromDER(der)
	if err != nil {
		t.Fatal(err)
	}

	new_der_from_pem, err := loaded_pubkey_from_pem.MarshalPKIXPublicKeyDER()
	if err != nil {
		t.Fatal(err)
	}

	new_der_from_der, err := loaded_pubkey_from_der.MarshalPKIXPublicKeyDER()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(new_der_from_der, tls_der) {
		ioutil.WriteFile("generated", []byte(hex.Dump(new_der_from_der)), 0644)
		ioutil.WriteFile("hardcoded", []byte(hex.Dump(tls_der)), 0644)
		t.Fatal("invalid public key der bytes")
	}

	if !bytes.Equal(new_der_from_pem, tls_der) {
		ioutil.WriteFile("generated", []byte(hex.Dump(new_der_from_pem)), 0644)
		ioutil.WriteFile("hardcoded", []byte(hex.Dump(tls_der)), 0644)
		t.Fatal("invalid public key der bytes")
	}
}

func TestRSAOAEP(t *testing.T) {
	t.Parallel()

	key, err := LoadPrivateKeyFromPEM(keyBytes)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("the quick brown fox jumps over the lazy dog")

	t.Run("encrypt and decrypt", func(t *testing.T) {
		t.Parallel()
		encrypted, err := key.EncryptOAEP(data, nil)
		if err != nil {
			t.Fatal(err)
		}
		decrypted, err := key.DecryptOAEP(encrypted, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, decrypted) {
			ioutil.WriteFile("plaintext", data, 0644)
			ioutil.WriteFile("decrypted", decrypted, 0644)
			t.Fatal("decrypted data different from original")
		}
	})

	t.Run("fail on nil input", func(t *testing.T) {
		t.Parallel()
		_, err := key.EncryptOAEP(nil, nil)
		if err == nil {
			t.Fatal("error expected for encryption with nil input")
		}
		_, err = key.DecryptOAEP(nil, nil)
		if err == nil {
			t.Fatal("error expected for decryption with nil input")
		}
	})

	t.Run("fail on wrong key type", func(t *testing.T) {
		t.Parallel()
		eckey, err := LoadPrivateKeyFromPEM(prime256v1KeyBytes)
		if err != nil {
			t.Skip("failed to load EC private key")
		}

		_, err = eckey.EncryptOAEP(data, nil)
		if err == nil {
			t.Fatal("error expected for encryption with wrong key type")
		}
		_, err = eckey.DecryptOAEP(data, nil)
		if err == nil {
			t.Fatal("error expected for decryption with wrong key type")
		}
	})

	t.Run("fail on decrypt with wrong key", func(t *testing.T) {
		t.Parallel()
		key2, err := GenerateRSAKeyWithExponent(1024, 0x10001)
		if err != nil {
			t.Skip("failed to generate extra key")
		}

		encrypted, err := key.EncryptOAEP(data, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = key2.DecryptOAEP(encrypted, nil)
		if err == nil {
			t.Fatal("expected error for decryption with wrong key")
		}
	})
	t.Run("sha256 oaep and mgf1", func(t *testing.T) {
		t.Parallel()
		opts := &OAEPOptions{
			OAEPDigest: SHA256_Method,
		}
		encrypted, err := key.EncryptOAEP(data, opts)
		if err != nil {
			t.Fatal(err)
		}
		decrypted, err := key.DecryptOAEP(encrypted, opts)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, decrypted) {
			ioutil.WriteFile("plaintext", data, 0644)
			ioutil.WriteFile("decrypted", decrypted, 0644)
			t.Fatal("decrypted data different from original")
		}

		_, err = key.DecryptOAEP(encrypted, nil)
		if err == nil {
			t.Fatal("expected error for decrypting with wrong digest")
		}
	})

	t.Run("sha256 oaep, sha1 mgf1", func(t *testing.T) {
		t.Parallel()
		opts := &OAEPOptions{
			OAEPDigest: SHA256_Method,
			MGF1Digest: SHA1_Method,
		}
		encrypted, err := key.EncryptOAEP(data, opts)
		if err != nil {
			t.Fatal(err)
		}
		decrypted, err := key.DecryptOAEP(encrypted, opts)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, decrypted) {
			ioutil.WriteFile("plaintext", data, 0644)
			ioutil.WriteFile("decrypted", decrypted, 0644)
			t.Fatal("decrypted data different from original")
		}

		_, err = key.DecryptOAEP(encrypted, nil)
		if err == nil {
			t.Fatal("expected error for decrypting with wrong digest")
		}
	})

	t.Run("with label", func(t *testing.T) {
		t.Parallel()
		opts := &OAEPOptions{
			Label: []byte("hellothere"),
		}
		encrypted, err := key.EncryptOAEP(data, opts)
		if err != nil {
			t.Fatal(err)
		}
		decrypted, err := key.DecryptOAEP(encrypted, opts)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, decrypted) {
			ioutil.WriteFile("plaintext", data, 0644)
			ioutil.WriteFile("decrypted", decrypted, 0644)
			t.Fatal("decrypted data different from original")
		}

		_, err = key.DecryptOAEP(encrypted, nil)
		if err == nil {
			t.Fatal("expected error for decrypting with wrong label")
		}
	})
}

func TestPSS(t *testing.T) {
	t.Parallel()

	key, err := LoadPrivateKeyFromPEM(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("the quick brown fox jumps over the lazy dog")

	hashSha256, err := SHA256(data)
	if err != nil {
		t.Fatal(err)
	}

	shouldSuceed := func(method Method, hash []byte, signSaltLen, verifySaltLen int) func(*testing.T) {
		return func(t *testing.T) {
			t.Parallel()
			sig, err := key.SignPSS(method, hash, signSaltLen)
			if err != nil {
				t.Fatal(err)
			}
			err = key.VerifyPSS(method, hash, sig, verifySaltLen)
			if err != nil {
				t.Fatal(err)
			}
		}
	}

	t.Run(
		"sha256 sign auto verify auto",
		shouldSuceed(SHA256_Method, hashSha256[:], PSSSaltLengthAuto, PSSSaltLengthAuto),
	)
	t.Run(
		"sha256 sign hashsize verify auto",
		shouldSuceed(SHA256_Method, hashSha256[:], PSSSaltLengthEqualsHash, PSSSaltLengthAuto),
	)
	t.Run(
		"sha256 sign fixed verify auto",
		shouldSuceed(SHA256_Method, hashSha256[:], 16, PSSSaltLengthAuto),
	)
	t.Run(
		"sha256 sign fixed verify fixed",
		shouldSuceed(SHA256_Method, hashSha256[:], 16, 16),
	)
}

func TestEncryptedPEM(t *testing.T) {
	t.Parallel()

	key, err := LoadPrivateKeyFromPEM(keyBytes)
	if err != nil {
		t.Fatal(err)
	}

	password := "a very secure password"
	cipher, err := GetCipherByNid(NID_aes_256_cbc)
	if err != nil {
		t.Fatal(err)
	}

	pem, err := key.MarshalPKCS1PrivateKeyPEMWithPassword(cipher, password)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("correct password", func(t *testing.T) {
		t.Parallel()
		_, err := LoadPrivateKeyFromPEMWithPassword(pem, password)
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("bad password", func(t *testing.T) {
		t.Parallel()
		_, err := LoadPrivateKeyFromPEMWithPassword(pem, "not the right password")
		if err == nil {
			t.Fatalf("expected decryption with wrong password to fail")
		}
	})
}
