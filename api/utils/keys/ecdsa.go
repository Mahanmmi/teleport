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
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"runtime"

	"github.com/gravitational/teleport/api/constants"

	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// ECDSAPrivateKey is an ecdsa.PrivateKey with additional methods
type ECDSAPrivateKey struct {
	*ecdsa.PrivateKey
	privateKeyDER []byte
	sshPub        ssh.PublicKey
}

// ParseECDSAPrivateKey parses an ECDSAPRivateKey key in SEC 1, ASN.1 DER form.
func ParseECDSAPrivateKey(keyDER []byte) (*ECDSAPrivateKey, error) {
	ecdsaPrivateKey, err := x509.ParseECPrivateKey(keyDER)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	key, err := NewECDSAPrivateKey(ecdsaPrivateKey)
	return key, trace.Wrap(err)
}

// NewECDSAPrivateKey creates a new ECDSAPrivateKey from a ecdsa.PrivateKey.
func NewECDSAPrivateKey(priv *ecdsa.PrivateKey) (*ECDSAPrivateKey, error) {
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	sshPub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &ECDSAPrivateKey{
		PrivateKey:    priv,
		privateKeyDER: keyDER,
		sshPub:        sshPub,
	}, nil
}

// Equal returns whether the given private key is equal to this key.
func (r *ECDSAPrivateKey) Equal(x crypto.PrivateKey) bool {
	switch priv := x.(type) {
	case *ECDSAPrivateKey:
		return r.PrivateKey.Equal(priv.PrivateKey)
	case *ecdsa.PrivateKey:
		return r.PrivateKey.Equal(priv)
	}
	return false
}

// PrivateKeyPEM returns the PEM encoded ECDSA private key.
func (r *ECDSAPrivateKey) PrivateKeyPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:    ecdsaPrivateKeyType,
		Headers: nil,
		Bytes:   r.privateKeyDER,
	})
}

// SSHPublicKey returns the ssh.PublicKey representiation of the public key.
func (r *ECDSAPrivateKey) SSHPublicKey() ssh.PublicKey {
	return r.sshPub
}

// TLSCertificate parses the given TLS certificate paired with the private key
// to rerturn a tls.Certificate, ready to be used in a TLS handshake.
func (r *ECDSAPrivateKey) TLSCertificate(certRaw []byte) (tls.Certificate, error) {
	cert, err := tls.X509KeyPair(certRaw, r.PrivateKeyPEM())
	return cert, trace.Wrap(err)
}

// AsAgentKeys converts Key struct to a []*agent.AddedKey. All elements
// of the []*agent.AddedKey slice need to be loaded into the agent!
func (r *ECDSAPrivateKey) AsAgentKeys(sshCert *ssh.Certificate) []agent.AddedKey {
	// put a teleport identifier along with the teleport user into the comment field
	comment := agentKeyComment{user: sshCert.KeyId}

	// On all OS'es, return the certificate with the private key embedded.
	agents := []agent.AddedKey{
		{
			PrivateKey:       r.PrivateKey,
			Certificate:      sshCert,
			Comment:          comment.String(),
			LifetimeSecs:     0,
			ConfirmBeforeUse: false,
		},
	}

	if runtime.GOOS != constants.WindowsOS {
		// On Unix, also return a lone private key.
		//
		// (2016-08-01) have a bug in how they use certificates that have been lo
		// This is done because OpenSSH clients older than OpenSSH 7.3/7.3p1aded
		// in an agent. Specifically when you add a certificate to an agent, you can't
		// just embed the private key within the certificate, you have to add the
		// certificate and private key to the agent separately. Teleport works around
		// this behavior to ensure OpenSSH interoperability.
		//
		// For more details see the following: https://bugzilla.mindrot.org/show_bug.cgi?id=2550
		// WARNING: callers expect the returned slice to be __exactly as it is__

		agents = append(agents, agent.AddedKey{
			PrivateKey:       r.PrivateKey,
			Certificate:      nil,
			Comment:          comment.String(),
			LifetimeSecs:     0,
			ConfirmBeforeUse: false,
		})
	}

	return agents
}
