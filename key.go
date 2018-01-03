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
import "C"

import (
	"errors"
	"io/ioutil"
	"runtime"
	"unsafe"
)

type Method *C.EVP_MD

var (
	SHA1_Method   Method = C.X_EVP_sha1()
	SHA256_Method Method = C.X_EVP_sha256()
	SHA512_Method Method = C.X_EVP_sha512()
)

// Constants for the various key types.
// Mapping of name -> NID taken from openssl/evp.h
const (
	KeyTypeNone    = NID_undef
	KeyTypeRSA     = NID_rsaEncryption
	KeyTypeRSA2    = NID_rsa
	KeyTypeDSA     = NID_dsa
	KeyTypeDSA1    = NID_dsa_2
	KeyTypeDSA2    = NID_dsaWithSHA
	KeyTypeDSA3    = NID_dsaWithSHA1
	KeyTypeDSA4    = NID_dsaWithSHA1_2
	KeyTypeDH      = NID_dhKeyAgreement
	KeyTypeDHX     = NID_dhpublicnumber
	KeyTypeEC      = NID_X9_62_id_ecPublicKey
	KeyTypeHMAC    = NID_hmac
	KeyTypeCMAC    = NID_cmac
	KeyTypeTLS1PRF = NID_tls1_prf
	KeyTypeHKDF    = NID_hkdf
)

const (
	// PSSSaltLengthAuto causes the salt in a PSS signature to be as large
	// as possible when signing, and to be auto-detected when verifying.
	PSSSaltLengthAuto int = -2
	// PSSSaltLengthEqualsHash causes the salt length to equal the length of
	// the hash used in the signature.
	PSSSaltLengthEqualsHash int = -1
)

// OAEPOptions contains optional parameters that may be specified when performing
// RSA-OAEP encryption/decryption operations.
//
// OAEPDigest and MGF1Digest may be used to specify the message digest
// algorithm to use for the padding and mask generation, respectively.
//
// If OAEPDigest is nil, SHA1 will be used.
// If MGF1Digest is nil, the same digest as OAEPDigest will be used.
//
// NOTE: In OpenSSL < v1.0.2, the digest used for both OAEP and MGF1 is
// hard-coded to SHA1.
// An error will be returned if either digest is set to anything other
// than SHA1 or nil.
//
// Label can be used to set the OAEP label.
//
// Note: In OpenSSL < v1.0.2, the OAEP label cannot be changed. Setting Label
// to a non-empty byte slice will cause the operation to return an error.
type OAEPOptions struct {
	OAEPDigest Method
	MGF1Digest Method
	Label      []byte
}

var defaultOAEPOptions = &OAEPOptions{
	OAEPDigest: nil,
	MGF1Digest: nil,
	Label:      nil,
}

type PublicKey interface {
	// Verifies the data signature using PKCS1.15
	VerifyPKCS1v15(method Method, data, sig []byte) error

	// VerifyPSS verifies that sig is a valid RSA-PSS signature.
	// The data must have been already hashed using digest, with the hash
	// specified in hashed.
	VerifyPSS(method Method, hashed, sig []byte, saltlen int) error

	// MarshalPKIXPublicKeyPEM converts the public key to PEM-encoded PKIX
	// format
	MarshalPKIXPublicKeyPEM() (pem_block []byte, err error)

	// MarshalPKIXPublicKeyDER converts the public key to DER-encoded PKIX
	// format
	MarshalPKIXPublicKeyDER() (der_block []byte, err error)

	// EncryptOAEP encrypts the given plaintext with the key using RSA-OAEP.
	// This method will return an error for non-RSA keys.
	EncryptOAEP(plaintext []byte, opts *OAEPOptions) (encrypted []byte, err error)

	// KeyType returns an identifier for what kind of key is represented by this
	// object.
	KeyType() NID

	// BaseType returns an identifier for what kind of key is represented
	// by this object.
	// Keys that share same algorithm but use different legacy formats
	// will have the same BaseType.
	//
	// For example, a key with a `KeyType() == KeyTypeRSA` and a key with a
	// `KeyType() == KeyTypeRSA2` would both have `BaseType() == KeyTypeRSA`.
	BaseType() NID

	// Free immediately frees the key, removing it from memory.
	// Any attempt to use the key after calling Free will fail.
	//
	// Note: keys are automatically freed when they are garbage collected,
	// so it is not necessary to manually call this method in most cases.
	// Only use this method if you have a need to immediately remove a key
	// from memory.
	Free()

	evpPKey() *C.EVP_PKEY
}

type PrivateKey interface {
	PublicKey

	// Signs the data using PKCS1.15
	SignPKCS1v15(Method, []byte) ([]byte, error)

	// SignPSS signs a hashed message using the RSA-PSS digital signature
	// algorithm. The message must have already been hashed using the specified
	// digest, with the hash specified in hashed.
	SignPSS(method Method, hashed []byte, saltlen int) (sig []byte, err error)

	// MarshalPKCS1PrivateKeyPEM converts the private key to PEM-encoded PKCS1
	// format
	MarshalPKCS1PrivateKeyPEM() (pem_block []byte, err error)

	// MarshalPKCS1PrivateKeyDER converts the private key to DER-encoded PKCS1
	// format
	MarshalPKCS1PrivateKeyDER() (der_block []byte, err error)

	// DecryptOAEP decrypts data that has been encrypted using RSA-OAEP.
	// This method will return an error for non-RSA keys.
	//
	// oaepDigest and mgf1Digest may be used to specify the message digest
	// algorithm to use for the padding and mask generation, respectively.
	//
	// If oaepDigest is nil, SHA1 will be used by default.
	// If mgf1Digest is nil, the same digest as oaepDigest will be used.
	//
	// NOTE: In OpenSSL < v1.0.2, the digest used for both OAEP and MGF1 is
	// hard-coded to SHA1.
	// An error will be returned if either digest is set to anything other
	// than SHA1 or nil.
	DecryptOAEP(encrypted []byte, opts *OAEPOptions) (plaintext []byte, err error)
}

type pKey struct {
	key *C.EVP_PKEY
}

func freePKey(p *pKey) {
	// Safe even if p.key == nil, as EVP_PKEY_free does nothing if the argument
	// is NULL
	C.X_EVP_PKEY_free(p.key)
	p.key = nil
}

func (key *pKey) evpPKey() *C.EVP_PKEY { return key.key }

func (key *pKey) Free() {
	freePKey(key)
}

func (key *pKey) KeyType() NID {
	return NID(C.EVP_PKEY_id(key.key))
}

func (key *pKey) BaseType() NID {
	return NID(C.EVP_PKEY_base_id(key.key))
}

func (key *pKey) SignPKCS1v15(method Method, data []byte) ([]byte, error) {
	ctx := C.X_EVP_MD_CTX_new()
	defer C.X_EVP_MD_CTX_free(ctx)

	if 1 != C.X_EVP_SignInit(ctx, method) {
		return nil, errors.New("signpkcs1v15: failed to init signature")
	}
	if len(data) > 0 {
		if 1 != C.X_EVP_SignUpdate(
			ctx, unsafe.Pointer(&data[0]), C.uint(len(data))) {
			return nil, errors.New("signpkcs1v15: failed to update signature")
		}
	}
	sig := make([]byte, C.X_EVP_PKEY_size(key.key))
	var sigblen C.uint
	if 1 != C.X_EVP_SignFinal(ctx,
		((*C.uchar)(unsafe.Pointer(&sig[0]))), &sigblen, key.key) {
		return nil, errors.New("signpkcs1v15: failed to finalize signature")
	}
	return sig[:sigblen], nil
}

func (key *pKey) VerifyPKCS1v15(method Method, data, sig []byte) error {
	ctx := C.X_EVP_MD_CTX_new()
	defer C.X_EVP_MD_CTX_free(ctx)

	if 1 != C.X_EVP_VerifyInit(ctx, method) {
		return errors.New("verifypkcs1v15: failed to init verify")
	}
	if len(data) > 0 {
		if 1 != C.X_EVP_VerifyUpdate(
			ctx, unsafe.Pointer(&data[0]), C.uint(len(data))) {
			return errors.New("verifypkcs1v15: failed to update verify")
		}
	}
	if 1 != C.X_EVP_VerifyFinal(ctx,
		((*C.uchar)(unsafe.Pointer(&sig[0]))), C.uint(len(sig)), key.key) {
		return errors.New("verifypkcs1v15: failed to finalize verify")
	}
	return nil
}

func (key *pKey) SignPSS(method Method, hashed []byte, saltlen int) ([]byte, error) {
	if key.BaseType() != KeyTypeRSA {
		return nil, errors.New("signrsapss: key type is not RSA")
	}

	ctx := C.EVP_PKEY_CTX_new(key.key, nil)
	if ctx == nil {
		return nil, errors.New("signrsapss: failed to create context")
	}
	defer C.EVP_PKEY_CTX_free(ctx)

	if C.EVP_PKEY_sign_init(ctx) != 1 {
		return nil, errors.New("signrsapss: failed to init sign")
	}

	if C.X_EVP_PKEY_CTX_set_rsa_padding(ctx, C.RSA_PKCS1_PSS_PADDING) != 1 {
		return nil, errors.New("signrsapss: failed to set padding to RSA-PSS")
	}

	if C.X_EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, C.int(saltlen)) != 1 {
		return nil, errors.New("signrsapss: failed to set salt length")
	}

	if C.X_EVP_PKEY_CTX_set_signature_md(ctx, method) != 1 {
		return nil, errors.New("signrsapss: failed to set message digest")
	}

	tbs := (*C.uchar)(&hashed[0])
	tbsLen := C.size_t(len(hashed))

	var sigBuffLen C.size_t
	if C.EVP_PKEY_sign(ctx, nil, &sigBuffLen, tbs, tbsLen) != 1 {
		return nil, errors.New("signrsapss: failed to determine buffer length")
	}

	sig := make([]byte, int(sigBuffLen))
	sigPtr := (*C.uchar)(&sig[0])
	if C.EVP_PKEY_sign(ctx, sigPtr, &sigBuffLen, tbs, tbsLen) != 1 {
		return nil, errors.New("signrsapss: failed to generate signature")
	}

	// sigBuffLen now contains the actual number of bytes written to sig
	return sig[:uint(sigBuffLen)], nil
}

func (key *pKey) VerifyPSS(method Method, hashed, sig []byte, saltlen int) error {
	if key.BaseType() != KeyTypeRSA {
		return errors.New("verifyrsapss: key type is not RSA")
	}

	ctx := C.EVP_PKEY_CTX_new(key.key, nil)
	if ctx == nil {
		return errors.New("verifyrsapss: failed to create context")
	}
	defer C.EVP_PKEY_CTX_free(ctx)

	if C.EVP_PKEY_verify_init(ctx) != 1 {
		return errors.New("verifyrsapss: failed to init sign")
	}

	if C.X_EVP_PKEY_CTX_set_rsa_padding(ctx, C.RSA_PKCS1_PSS_PADDING) != 1 {
		return errors.New("verifyrsapss: failed to set padding to RSA-PSS")
	}

	if C.X_EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, C.int(saltlen)) != 1 {
		return errors.New("verifyrsapss: failed to set salt length")
	}

	if C.X_EVP_PKEY_CTX_set_signature_md(ctx, method) != 1 {
		return errors.New("verifyrsapss: failed to set message digest")
	}

	tbs := (*C.uchar)(&hashed[0])
	tbsLen := C.size_t(len(hashed))
	sigPtr := (*C.uchar)(&sig[0])
	sigLen := C.size_t(len(sig))

	if C.EVP_PKEY_verify(ctx, sigPtr, sigLen, tbs, tbsLen) != 1 {
		return errors.New("verifyrsapss: signature is invalid")
	}

	return nil
}

func (key *pKey) MarshalPKCS1PrivateKeyPEM() (pem_block []byte,
	err error) {
	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, errors.New("failed to allocate memory BIO")
	}
	defer C.BIO_free(bio)

	// PEM_write_bio_PrivateKey_traditional will use the key-specific PKCS1
	// format if one is available for that key type, otherwise it will encode
	// to a PKCS8 key.
	if int(C.X_PEM_write_bio_PrivateKey_traditional(bio, key.key, nil, nil,
		C.int(0), nil, nil)) != 1 {
		return nil, errors.New("failed dumping private key")
	}

	return ioutil.ReadAll(asAnyBio(bio))
}

func (key *pKey) MarshalPKCS1PrivateKeyDER() (der_block []byte,
	err error) {
	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, errors.New("failed to allocate memory BIO")
	}
	defer C.BIO_free(bio)

	if int(C.i2d_PrivateKey_bio(bio, key.key)) != 1 {
		return nil, errors.New("failed dumping private key der")
	}

	return ioutil.ReadAll(asAnyBio(bio))
}

func (key *pKey) MarshalPKIXPublicKeyPEM() (pem_block []byte,
	err error) {
	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, errors.New("failed to allocate memory BIO")
	}
	defer C.BIO_free(bio)

	if int(C.PEM_write_bio_PUBKEY(bio, key.key)) != 1 {
		return nil, errors.New("failed dumping public key pem")
	}

	return ioutil.ReadAll(asAnyBio(bio))
}

func (key *pKey) MarshalPKIXPublicKeyDER() (der_block []byte,
	err error) {
	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, errors.New("failed to allocate memory BIO")
	}
	defer C.BIO_free(bio)

	if int(C.i2d_PUBKEY_bio(bio, key.key)) != 1 {
		return nil, errors.New("failed dumping public key der")
	}

	return ioutil.ReadAll(asAnyBio(bio))
}

func (key *pKey) EncryptOAEP(plaintext []byte, opts *OAEPOptions) (encrypted []byte, err error) {
	if opts == nil {
		opts = defaultOAEPOptions
	}

	if plaintext == nil {
		return nil, errors.New("data to encrypt cannot be nil")
	}
	if key.BaseType() != KeyTypeRSA {
		return nil, errors.New("wrong key type for RSA-OAEP")
	}

	// Create a new context
	ctx := C.EVP_PKEY_CTX_new(key.key, nil)
	if ctx == nil {
		return nil, errors.New("failed creating encryption context")
	}
	defer C.EVP_PKEY_CTX_free(ctx)

	// Initialize the context for encryption
	rc := C.EVP_PKEY_encrypt_init(ctx)
	if rc != 1 {
		return nil, errors.New("failed initializing encryption context")
	}

	// Set context to use RSA OAEP padding
	rc = C.X_EVP_PKEY_CTX_set_rsa_padding(ctx, C.RSA_PKCS1_OAEP_PADDING)
	if rc != 1 {
		return nil, errors.New("failed setting padding to RSA OAEP")
	}

	// Set OAEP digest if specified
	if opts.OAEPDigest != nil {
		if C.X_EVP_PKEY_CTX_set_rsa_oaep_md(ctx, opts.OAEPDigest) != 1 {
			return nil, errors.New("failed setting OAEP message digest")
		}
	}

	// Set MGF1 digest if specified
	if opts.MGF1Digest != nil {
		if C.X_EVP_PKEY_CTX_set_rsa_mgf1_md_oaep_compat(ctx, opts.MGF1Digest) != 1 {
			return nil, errors.New("failed setting MGF1 message digest")
		}
	}

	// Set label if specified
	if len(opts.Label) > 0 {
		if C.X_EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, unsafe.Pointer(&opts.Label[0]), C.int(len(opts.Label))) != 1 {
			return nil, errors.New("failed setting OAEP label")
		}
	}

	input := (*C.uchar)(&plaintext[0])
	inputLen := C.size_t(len(plaintext))
	var outLen C.size_t

	// Determine the size of the output buffer
	rc = C.EVP_PKEY_encrypt(ctx, nil, &outLen, input, inputLen)
	if rc != 1 {
		return nil, errors.New("failed determining output length")
	}

	// Allocate a buffer for the output
	encrypted = make([]byte, int(outLen))

	// Encrypt the data into the buffer
	rc = C.EVP_PKEY_encrypt(ctx, (*C.uchar)(&encrypted[0]), &outLen, input, inputLen)
	if rc != 1 {
		return nil, errors.New("failed encrypting data")
	}

	return encrypted[:outLen], nil
}

func (key *pKey) DecryptOAEP(encrypted []byte, opts *OAEPOptions) (plaintext []byte, err error) {
	if opts == nil {
		opts = defaultOAEPOptions
	}

	if encrypted == nil {
		return nil, errors.New("data to decrypt cannot be nil")
	}
	if key.BaseType() != KeyTypeRSA {
		return nil, errors.New("wrong key type for RSA-OAEP")
	}

	// Create a new context
	ctx := C.EVP_PKEY_CTX_new(key.key, nil)
	if ctx == nil {
		return nil, errors.New("failed creating decryption context")
	}
	defer C.EVP_PKEY_CTX_free(ctx)

	// Initialize the context for decryption
	rc := C.EVP_PKEY_decrypt_init(ctx)
	if rc != 1 {
		return nil, errors.New("failed initializing decryption context")
	}

	// Set context to use RSA OAEP padding
	rc = C.X_EVP_PKEY_CTX_set_rsa_padding(ctx, C.RSA_PKCS1_OAEP_PADDING)
	if rc != 1 {
		return nil, errors.New("failed setting padding to RSA OAEP")
	}

	// Set OAEP digest if specified
	if opts.OAEPDigest != nil {
		if C.X_EVP_PKEY_CTX_set_rsa_oaep_md(ctx, opts.OAEPDigest) != 1 {
			return nil, errors.New("failed setting OAEP message digest")
		}
	}

	// Set MGF1 digest if specified
	if opts.MGF1Digest != nil {
		if C.X_EVP_PKEY_CTX_set_rsa_mgf1_md_oaep_compat(ctx, opts.MGF1Digest) != 1 {
			return nil, errors.New("failed setting MGF1 message digest")
		}
	}

	// Set label if specified
	if len(opts.Label) > 0 {
		if C.X_EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, unsafe.Pointer(&opts.Label[0]), C.int(len(opts.Label))) != 1 {
			return nil, errors.New("failed setting OAEP label")
		}
	}

	input := (*C.uchar)(&encrypted[0])
	inputLen := C.size_t(len(encrypted))
	var outLen C.size_t

	// Determine the size of the output buffer
	rc = C.EVP_PKEY_decrypt(ctx, nil, &outLen, input, inputLen)
	if rc != 1 {
		return nil, errors.New("failed determining output length")
	}

	plaintext = make([]byte, int(outLen))

	// Encrypt the data into the buffer
	rc = C.EVP_PKEY_decrypt(ctx, (*C.uchar)(&plaintext[0]), &outLen, input, inputLen)
	if rc != 1 {
		return nil, errors.New("failed decrypting data")
	}

	// Actual # of bytes in buffer now in outLen
	return plaintext[:outLen], nil
}

// LoadPrivateKeyFromPEM loads a private key from a PEM-encoded block.
func LoadPrivateKeyFromPEM(pem_block []byte) (PrivateKey, error) {
	if len(pem_block) == 0 {
		return nil, errors.New("empty pem block")
	}
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pem_block[0]),
		C.int(len(pem_block)))
	if bio == nil {
		return nil, errors.New("failed creating bio")
	}
	defer C.BIO_free(bio)

	key := C.PEM_read_bio_PrivateKey(bio, nil, nil, nil)
	if key == nil {
		return nil, errors.New("failed reading private key")
	}

	p := &pKey{key: key}
	runtime.SetFinalizer(p, freePKey)
	return p, nil
}

// LoadPrivateKeyFromPEMWithPassword loads a private key from a PEM-encoded block.
func LoadPrivateKeyFromPEMWithPassword(pem_block []byte, password string) (
	PrivateKey, error) {
	if len(pem_block) == 0 {
		return nil, errors.New("empty pem block")
	}
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pem_block[0]),
		C.int(len(pem_block)))
	if bio == nil {
		return nil, errors.New("failed creating bio")
	}
	defer C.BIO_free(bio)
	cs := C.CString(password)
	defer C.free(unsafe.Pointer(cs))
	key := C.PEM_read_bio_PrivateKey(bio, nil, nil, unsafe.Pointer(cs))
	if key == nil {
		return nil, errors.New("failed reading private key")
	}

	p := &pKey{key: key}
	runtime.SetFinalizer(p, freePKey)
	return p, nil
}

// LoadPrivateKeyFromDER loads a private key from a DER-encoded block.
func LoadPrivateKeyFromDER(der_block []byte) (PrivateKey, error) {
	if len(der_block) == 0 {
		return nil, errors.New("empty der block")
	}
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&der_block[0]),
		C.int(len(der_block)))
	if bio == nil {
		return nil, errors.New("failed creating bio")
	}
	defer C.BIO_free(bio)

	key := C.d2i_PrivateKey_bio(bio, nil)
	if key == nil {
		return nil, errors.New("failed reading private key der")
	}

	p := &pKey{key: key}
	runtime.SetFinalizer(p, freePKey)
	return p, nil
}

// LoadPrivateKeyFromPEMWidthPassword loads a private key from a PEM-encoded block.
// Backwards-compatible with typo
func LoadPrivateKeyFromPEMWidthPassword(pem_block []byte, password string) (
	PrivateKey, error) {
	return LoadPrivateKeyFromPEMWithPassword(pem_block, password)
}

// LoadPublicKeyFromPEM loads a public key from a PEM-encoded block.
func LoadPublicKeyFromPEM(pem_block []byte) (PublicKey, error) {
	if len(pem_block) == 0 {
		return nil, errors.New("empty pem block")
	}
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pem_block[0]),
		C.int(len(pem_block)))
	if bio == nil {
		return nil, errors.New("failed creating bio")
	}
	defer C.BIO_free(bio)

	key := C.PEM_read_bio_PUBKEY(bio, nil, nil, nil)
	if key == nil {
		return nil, errors.New("failed reading public key der")
	}

	p := &pKey{key: key}
	runtime.SetFinalizer(p, freePKey)
	return p, nil
}

// LoadPublicKeyFromDER loads a public key from a DER-encoded block.
func LoadPublicKeyFromDER(der_block []byte) (PublicKey, error) {
	if len(der_block) == 0 {
		return nil, errors.New("empty der block")
	}
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&der_block[0]),
		C.int(len(der_block)))
	if bio == nil {
		return nil, errors.New("failed creating bio")
	}
	defer C.BIO_free(bio)

	key := C.d2i_PUBKEY_bio(bio, nil)
	if key == nil {
		return nil, errors.New("failed reading public key der")
	}

	p := &pKey{key: key}
	runtime.SetFinalizer(p, freePKey)
	return p, nil
}

// GenerateRSAKey generates a new RSA private key with an exponent of 3.
func GenerateRSAKey(bits int) (PrivateKey, error) {
	return GenerateRSAKeyWithExponent(bits, 3)
}

// GenerateRSAKeyWithExponent generates a new RSA private key.
func GenerateRSAKeyWithExponent(bits int, exponent int) (PrivateKey, error) {
	rsa := C.RSA_generate_key(C.int(bits), C.ulong(exponent), nil, nil)
	if rsa == nil {
		return nil, errors.New("failed to generate RSA key")
	}
	key := C.X_EVP_PKEY_new()
	if key == nil {
		return nil, errors.New("failed to allocate EVP_PKEY")
	}
	if C.X_EVP_PKEY_assign_charp(key, C.EVP_PKEY_RSA, (*C.char)(unsafe.Pointer(rsa))) != 1 {
		C.X_EVP_PKEY_free(key)
		return nil, errors.New("failed to assign RSA key")
	}
	p := &pKey{key: key}
	runtime.SetFinalizer(p, freePKey)
	return p, nil
}

// GenerateECKey generates a new elliptic curve private key on the speicified
// curve.
func GenerateECKey(curve EllipticCurve) (PrivateKey, error) {

	// Create context for parameter generation
	paramCtx := C.EVP_PKEY_CTX_new_id(C.EVP_PKEY_EC, nil)
	if paramCtx == nil {
		return nil, errors.New("failed creating EC parameter generation context")
	}
	defer C.EVP_PKEY_CTX_free(paramCtx)

	// Intialize the parameter generation
	if int(C.EVP_PKEY_paramgen_init(paramCtx)) != 1 {
		return nil, errors.New("failed initializing EC parameter generation context")
	}

	// Set curve in EC parameter generation context
	if int(C.X_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(paramCtx, C.int(curve))) != 1 {
		return nil, errors.New("failed setting curve in EC parameter generation context")
	}

	// Create parameter object
	var params *C.EVP_PKEY
	if int(C.EVP_PKEY_paramgen(paramCtx, &params)) != 1 {
		return nil, errors.New("failed creating EC key generation parameters")
	}
	defer C.EVP_PKEY_free(params)

	// Create context for the key generation
	keyCtx := C.EVP_PKEY_CTX_new(params, nil)
	if keyCtx == nil {
		return nil, errors.New("failed creating EC key generation context")
	}
	defer C.EVP_PKEY_CTX_free(keyCtx)

	// Generate the key
	var privKey *C.EVP_PKEY
	if int(C.EVP_PKEY_keygen_init(keyCtx)) != 1 {
		return nil, errors.New("failed initializing EC key generation context")
	}
	if int(C.EVP_PKEY_keygen(keyCtx, &privKey)) != 1 {
		return nil, errors.New("failed generating EC private key")
	}

	p := &pKey{key: privKey}
	runtime.SetFinalizer(p, freePKey)
	return p, nil
}
