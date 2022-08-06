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

// Package keys defines common interfaces for Teleport client keys.
package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	pkcs8PrivateKeyType      = "PRIVATE KEY"
	rsaPrivateKeyType        = "RSA PRIVATE KEY"
	ecdsaPrivateKeyType      = "EC PRIVATE KEY"
	pivYubikeyPrivateKeyType = "PIV YUBIKEY PRIVATE KEY"
)

// PrivateKey implements crypto.PrivateKey and crypto.Signer, with additional helper methods
// for performing TLS/SSH handshakes, storing agent keys, and storing private key data.
type PrivateKey interface {
	crypto.Signer

	// Equal returns whether the given key is equal to this key
	Equal(x crypto.PrivateKey) bool

	// PrivateKeyPEM returns PEM encoded private key data. This may be data necessary
	// to retrieve the key, such as a Yubikey serial number and slot, or it can be a
	// PKCS marshaled private key.
	//
	// The resulting PEM encoded data should only be decoded with ParsePrivateKey to
	// prevent errors from parsing non PKCS marshaled keys, such as a PIV key.
	PrivateKeyPEM() []byte

	// SSHPublicKey returns the ssh.PublicKey representiation of the public key.
	SSHPublicKey() ssh.PublicKey

	// TLSCertificate parses the given TLS certificate paired with the private key
	// to rerturn a tls.Certificate, ready to be used in a TLS handshake.
	TLSCertificate(tlsCert []byte) (tls.Certificate, error)

	// AsAgentKeys a set of agent keys for the given ssh.Certificate and private key.
	AsAgentKeys(*ssh.Certificate) []agent.AddedKey
}

// ParsePrivateKey returns the PrivateKey for the given key PEM block.
func ParsePrivateKey(keyPEM []byte) (PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, trace.BadParameter("expected PEM encoded private key")
	}

	switch block.Type {
	case rsaPrivateKeyType:
		return parseRSAPrivateKey(block.Bytes)
	case ecdsaPrivateKeyType:
		return parseECDSAPrivateKey(block.Bytes)
	case pkcs8PrivateKeyType:
		priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		switch priv := priv.(type) {
		case *rsa.PrivateKey:
			return NewRSAPrivateKey(priv)
		case *ecdsa.PrivateKey:
			return NewECDSAPrivateKey(priv)
		case ed25519.PrivateKey:
			return NewED25519(priv)
		default:
			return nil, trace.BadParameter("unknown private key type in PKCS#8 wrapping")
		}
	case pivYubikeyPrivateKeyType:
		return parseYubikeyPrivateKey(block.Bytes)
	default:
		return nil, trace.BadParameter("unexpected private key PEM type %q", block.Type)
	}
}

// LoadPrivateKey returns the PrivateKey for the given key file.
func LoadPrivateKey(keyFile string) (PrivateKey, error) {
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, trace.ConvertSystemError(err)
	}

	priv, err := ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return priv, nil
}

// LoadX509KeyPair parse a tls.Certificate from a private key file and certificate file.
// This should be used instead of tls.LoadX509KeyPair to support non-raw private keys, like PIV keys.
func LoadX509KeyPair(certFile, keyFile string) (tls.Certificate, error) {
	keyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, trace.ConvertSystemError(err)
	}

	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, trace.ConvertSystemError(err)
	}

	tlsCert, err := X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return tls.Certificate{}, trace.Wrap(err)
	}

	return tlsCert, nil
}

// X509KeyPair parse a tls.Certificate from a private key PEM and certificate PEM.
// This should be used instead of tls.X509KeyPair to support non-raw private keys, like PIV keys.
func X509KeyPair(certPEMBlock, keyPEMBlock []byte) (tls.Certificate, error) {
	priv, err := ParsePrivateKey(keyPEMBlock)
	if err != nil {
		return tls.Certificate{}, trace.Wrap(err)
	}

	tlsCert, err := priv.TLSCertificate(certPEMBlock)
	if err != nil {
		return tls.Certificate{}, trace.Wrap(err)
	}

	return tlsCert, nil
}

// GetRSAPrivateKeyPEM returns a PEM encoded RSA private key for the given key.
// If the given key is not an RSA key, then an error will be returned.
//
// This is used by some integrations which currently only support raw RSA private keys,
// like Kubernetes, MongoDB, and PPK files for windows.
func GetRSAPrivateKeyPEM(k PrivateKey) ([]byte, error) {
	if _, ok := k.(*RSAPrivateKey); !ok {
		return nil, trace.BadParameter("cannot get rsa key PEM for private key of type %T", k)
	}
	return k.PrivateKeyPEM(), nil
}

type agentKeyComment struct {
	user string
}

func (a *agentKeyComment) String() string {
	return fmt.Sprintf("teleport:%s", a.user)
}
