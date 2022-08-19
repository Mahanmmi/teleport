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
	"crypto/tls"
	"encoding/pem"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/go-piv/piv-go/piv"
	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	defaultSlot = piv.SlotAuthentication
)

// GenerateYubikeyPrivateKey connects to the yubikey with the given serial number
// and generates a new private key on the given PIV slot with the given policies.
func GenerateYubikeyPrivateKey(serialNumber string, touchRequired bool) (*YubikeyPrivateKey, error) {
	y, err := findYubikey(serialNumber)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return y.generatePrivateKey(touchRequired)
}

// YubikeyPrivateKey is a Yubikey PIV private key. Cryptographical operations open
// a new temporary connection to the PIV card to perform the operation.
type YubikeyPrivateKey struct {
	*yubikey
	pub    crypto.PublicKey
	sshPub ssh.PublicKey
}

func newYubikeyPrivateKey(y *yubikey, pub crypto.PublicKey) (*YubikeyPrivateKey, error) {
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &YubikeyPrivateKey{
		yubikey: y,
		pub:     pub,
		sshPub:  sshPub,
	}, nil
}

func parseYubikeyPrivateKey(keyData []byte) (*YubikeyPrivateKey, error) {
	data := strings.Split(string(keyData), keyDataSeparator)
	if len(data) != 2 {
		return nil, trace.BadParameter("expected string like %q, got %q", "<serial_number>+<piv_slot>", keyData)
	}

	serialNumber := data[0]
	pivSlot, err := ParsePIVSlot(data[1])
	if err != nil {
		return nil, trace.Wrap(err)
	}

	y, err := findYubikey(serialNumber)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	priv, err := y.getPrivateKey(pivSlot)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return priv, nil
}

// Public returns the public key corresponding to this private key.
func (y *YubikeyPrivateKey) Public() crypto.PublicKey {
	return y.pub
}

// Sign implements crypto.Signer.
func (y *YubikeyPrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	yk, err := y.open()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer yk.Close()

	privateKey, err := yk.PrivateKey(defaultSlot, y.pub, piv.KeyAuth{})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return privateKey.(crypto.Signer).Sign(rand, digest, opts)
}

// Equal returns whether the given private key is equal to this one.
func (y *YubikeyPrivateKey) Equal(x crypto.PrivateKey) bool {
	switch other := x.(type) {
	case *YubikeyPrivateKey:
		return y.Public().(interface{ Equal(x crypto.PublicKey) bool }).Equal(other.Public())
	default:
		return false
	}
}

// PrivateKeyPEM returns PEM encoded data about this yubikey private key.
func (y *YubikeyPrivateKey) PrivateKeyPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:    pivYubikeyPrivateKeyType,
		Headers: nil,
		Bytes:   []byte(y.keyData()),
	})
}

var keyDataSeparator = "+"

func (y *YubikeyPrivateKey) keyData() string {
	return strings.Join([]string{strconv.FormatUint(uint64(y.serialNumber), 10), defaultSlot.String()}, keyDataSeparator)
}

// SSHPublicKey returns the ssh.PublicKey representiation of the public key.
func (y *YubikeyPrivateKey) SSHPublicKey() ssh.PublicKey {
	return y.sshPub
}

// TLSCertificate parses the given TLS certificate paired with the private key
// to rerturn a tls.Certificate, ready to be used in a TLS handshake.
func (y *YubikeyPrivateKey) TLSCertificate(cert []byte) (tls.Certificate, error) {
	certPEMBlock, _ := pem.Decode(cert)
	return tls.Certificate{
		Certificate: [][]byte{certPEMBlock.Bytes},
		PrivateKey:  y,
	}, nil
}

// AsAgentKeys returns an empty list, because x/crypto/ssh/agent does not support
// adding token agent keys currently.
func (y *YubikeyPrivateKey) AsAgentKeys(cert *ssh.Certificate) []agent.AddedKey {
	return []agent.AddedKey{}
}

func (y *YubikeyPrivateKey) GetAttestationCerts() (slot, attestation []byte, err error) {
	yk, err := y.open()
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	defer yk.Close()

	slotCert, err := yk.Attest(defaultSlot)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	attestationCert, err := yk.AttestationCertificate()
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}

	return slotCert.Raw, attestationCert.Raw, nil
}

// yubikey is a specific yubikey PIV card.
type yubikey struct {
	// card is a reader name used to find and connect to this yubikey.
	// This value may change between OS's, or with other system changes.
	card string

	// serialNumber is the yubikey's 8 digit serial number.
	serialNumber uint32
}

func newYubikey(card string) (*yubikey, error) {
	y := &yubikey{card: card}

	yk, err := y.open()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer yk.Close()

	y.serialNumber, err = yk.Serial()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return y, nil
}

// generatePrivateKey generates a new private key from the given PIV slot with the given PIV policies.
func (y *yubikey) generatePrivateKey(touchRequired bool) (*YubikeyPrivateKey, error) {
	yk, err := y.open()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer yk.Close()

	touchPolicy := piv.TouchPolicyNever
	if touchRequired {
		touchPolicy = piv.TouchPolicyCached
	}

	pub, err := yk.GenerateKey(
		piv.DefaultManagementKey,
		defaultSlot,
		piv.Key{
			Algorithm:   piv.AlgorithmEC256,
			PINPolicy:   piv.PINPolicyNever,
			TouchPolicy: touchPolicy,
		},
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return newYubikeyPrivateKey(y, pub)
}

// getPrivateKey gets an existing private key from the given PIV slot.
func (y *yubikey) getPrivateKey(slot piv.Slot) (*YubikeyPrivateKey, error) {
	yk, err := y.open()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer yk.Close()

	slotCert, err := yk.Attest(slot)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	attestationCert, err := yk.AttestationCertificate()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	_, err = piv.Verify(attestationCert, slotCert)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return newYubikeyPrivateKey(y, slotCert.PublicKey)
}

// open a connection to yubikey PIV module. The returned connection should be closed once
// it's been used. The yubikey PIV module itself takes some additional time to handle closed
// connections, so we use a retry loop to give the PIV module time to close prior connections.
func (y *yubikey) open() (yk *piv.YubiKey, err error) {
	isRetryError := func(err error) bool {
		retryError := "connecting to smart card: the smart card cannot be accessed because of other connections outstanding"
		return strings.Contains(err.Error(), retryError)
	}

	var maxRetries int = 100
	for i := 0; i < maxRetries; i++ {
		yk, err = piv.Open(y.card)
		if err == nil {
			return yk, nil
		}

		if !isRetryError(err) {
			return nil, trace.Wrap(err)
		}

		time.Sleep(time.Millisecond * 100)
	}

	return nil, trace.Wrap(err)
}

func findYubikey(serialNumber string) (*yubikey, error) {
	yubikeyCards, err := findYubikeyCards()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	for _, card := range yubikeyCards {
		y, err := newYubikey(card)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		if serialNumber == "" || strconv.FormatUint(uint64(y.serialNumber), 10) == serialNumber {
			return y, nil
		}
	}

	return nil, trace.NotFound("no yubikey device found with serial number %q", serialNumber)
}

func findYubikeyCards() ([]string, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var yubikeyCards []string
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), PIVCardTypeYubikey) {
			yubikeyCards = append(yubikeyCards, card)
		}
	}

	if len(yubikeyCards) == 0 {
		return nil, trace.NotFound("no yubikey devices found")
	}

	return yubikeyCards, nil
}
