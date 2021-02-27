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
}
