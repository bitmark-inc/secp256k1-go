// Copyright 2015 Jeffrey Wilcke, Felix Lange, Gustav Simonsson. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

package secp256k1

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSignAndVerifySignature(t *testing.T) {
	// short sig (serialized as 71 bytes)
	message := "randomString"

	privateKeyBytes, _ := hex.DecodeString("3de2fed8700e252d02026fec2d061b07ecc9fd11afa1f1321fc28b199d83688d")
	x, y := S256().ScalarBaseMult(privateKeyBytes)
	publicKeyBytes := elliptic.MarshalCompressed(S256(), x, y)
	assert.Equal(t, "02a0a8f329b2b14454fa9c757743c909595503e5a3fdb142e112d9f3c100c1a972", hex.EncodeToString(publicKeyBytes))

	hash := sha256.Sum256([]byte(message))
	sig, err := Sign(hash[:], privateKeyBytes)
	assert.NoError(t, err)
	assert.Equal(t, "3045022100a439460e6c0406e70397bd754fc21808860798f8df9c84c5e5cb3d62872dfc85022068c7336a801023f83ab82b9ef49228e2cc9807a389027d921af56d829ec00fd0", hex.EncodeToString(sig))

	assert.True(t, VerifySignature(publicKeyBytes, hash[:], sig))

	// short sig (serialized as 70 bytes)
	message = "1614571504898"

	privateKeyBytes, _ = hex.DecodeString("fd433f2b540ae869d0d4789b298c47a97915700e2b1732e6edeaff52fd6ef3f9")
	x, y = S256().ScalarBaseMult(privateKeyBytes)
	publicKeyBytes = elliptic.MarshalCompressed(S256(), x, y)

	hash = sha256.Sum256([]byte(message))
	sig, err = Sign(hash[:], privateKeyBytes)
	assert.NoError(t, err)
	assert.Equal(t, "304402200447f882e88e85794d6f9badc6b627f95fbde41bc51ef01359ad1cee8c49760f02200f99f23acb492cae33fb3a647139793381c4cc84f3894c283d6e2fc404c8d7b3", hex.EncodeToString(sig))

	assert.True(t, VerifySignature(publicKeyBytes, hash[:], sig))
}
