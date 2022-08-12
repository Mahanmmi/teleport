/*
Copyright 2022 Gravitational, Inc.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package keys

import (
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestYubikeyPrivateKey tests generating, retrieving, and signing with a YubikeyPrivateKey.
// This test expects default PIV settings and will overwrite any data on slot 9a.
func TestYubikeyPrivateKey(t *testing.T) {
	if os.Getenv("TELEPORT_TEST_YUBIKEY_PIV") == "" {
		t.Skipf("Skipping TestGenerateYubikeyPrivateKey because TELEPORT_TEST_YUBIKEY_PIV is not set")
	}

	y, err := findYubikey("")
	require.NoError(t, err)

	// Generate a new YubikeyPrivateKey
	priv1, err := y.generatePrivateKey()
	require.NoError(t, err)

	// Generate another YubikeyPrivateKey and confirm the key changed
	priv2, err := y.generatePrivateKey()
	require.NoError(t, err)
	require.False(t, priv2.Equal(priv1))

	// Test creating a self signed certificate with the key
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
	}
	_, err = x509.CreateCertificate(rand.Reader, template, template, priv2.Public(), priv2)
	require.NoError(t, err)

	// Marshal the private key into PEM encoded key data and parse it. We should get the same key back.
	retrievePriv, err := ParsePrivateKey(priv2.PrivateKeyPEM())
	require.NoError(t, err)
	require.True(t, retrievePriv.Equal(priv2))
}
