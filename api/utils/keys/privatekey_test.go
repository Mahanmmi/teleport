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
	"crypto/tls"
	"testing"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"
)

// TestParsePrivateKey tests that ParsePrivateKey successfully parses private key PEM.
func TestParsePrivateKey(t *testing.T) {
	for _, tt := range []struct {
		desc        string
		keyPEM      []byte
		assertError require.ErrorAssertionFunc
		assertKey   require.ValueAssertionFunc
	}{
		{
			desc:   "invalid PEM",
			keyPEM: []byte(`non-pem data`),
			assertError: func(t require.TestingT, err error, i ...interface{}) {
				require.True(t, trace.IsBadParameter(err), "expected trace.BadParameter, got %T", err)
			},
			assertKey: require.Nil,
		},
		{
			desc: "invalid type",
			keyPEM: []byte(`-----BEGIN INVALID KEY-----
-----END INVALID KEY-----
`),
			assertError: func(t require.TestingT, err error, i ...interface{}) {
				require.True(t, trace.IsBadParameter(err), "expected trace.BadParameter, got %T", err)
			},
			assertKey: require.Nil,
		},
		{
			desc:        "rsa key",
			keyPEM:      rsaKeyPEM,
			assertError: require.NoError,
			assertKey: func(tt require.TestingT, key interface{}, i2 ...interface{}) {
				require.IsType(t, &RSAPrivateKey{}, key)
			},
		},
		{
			desc:        "ecdsa key",
			keyPEM:      ecdsaKeyPEM,
			assertError: require.NoError,
			assertKey: func(tt require.TestingT, key interface{}, i2 ...interface{}) {
				require.IsType(t, &ECDSAPrivateKey{}, key)
			},
		},
		{
			desc:        "ed25519 key",
			keyPEM:      ed25519KeyPEM,
			assertError: require.NoError,
			assertKey: func(tt require.TestingT, key interface{}, i2 ...interface{}) {
				require.IsType(t, &ED25519PrivateKey{}, key)
			},
		},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			priv, err := ParsePrivateKey(tt.keyPEM)
			tt.assertError(t, err)
			tt.assertKey(t, priv)
		})
	}
}

// TestX509KeyPair tests that X509KeyPair returns the same value as tls.X509KeyPair
func TestX509KeyPair(t *testing.T) {
	expectCert, err := tls.X509KeyPair(rsaCertPEM, rsaKeyPEM)
	require.NoError(t, err)

	tlsCert, err := X509KeyPair(rsaCertPEM, rsaKeyPEM)
	require.NoError(t, err)

	require.Equal(t, expectCert, tlsCert)
}

var (
	// generated with `openssl req -x509 -out rsa.crt -keyout rsa.key -newkey rsa:2048 -nodes -sha256`
	rsaKeyPEM = []byte(`-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCv3j2mB1ZvxjW3
ncCTbCWB0u0xP2vdlAsKBZ7iym3U3yTgXuVp+CbBrUMU0xYtFEqCre3q81kc53GY
/aatE4a/Nq+HTpTarkmPh/txOL8VdMESwgdlQEhqEmVqFuyBPDHp0MWJsX/4SAhW
N3uee4zOngvcP5c+DE00o37SgSRLbBP2Etdmsvm+dPqFQ+iPUKkgBxYYJFVMOyxU
tg6UUtXLJ+ypjLkx1dVt5zTakFT3GuM9D9rsyJ3QbtD4H/u8IVV7OTfI0p5Fg6lh
dyKnmw8CK5zIaX27MATOEb8PlreL6GdldLBWl8bUGb4Ct+trokAmIPVzLj0zV5Cv
uiHbVLBjAgMBAAECggEAeMVIVpShYf6ecuptDY/trdp4MiKYY0A/2HEFrD5Q8CcQ
vtfL+VqE2umtsEZI60oM5PKl+HuGTZgOZX6CkEZheTwHjAaFqCqZr2w1WooahpR3
5fbCd2COmfDqHdGCNjltGWDZ1nXDKG/m8bYGOU4k4tqb0HMG3IA8IJLKC6rNjtCT
1s12KWr55qUQ+ZqUYhnt06kz4ShPGKAD/q6z8XUmr9xRrxbipGcN4yGQJXHVViPO
NxnDgQtJ/P7ONA00fSyPHMOOSh/h9wr6sLMxEJYOgsIIvLL88gibKKBCvS9GB8H4
MkchCi2sJSJN+7tiwYEFjXlXghfbMX38Dojtpry0YQKBgQDnky8+fG1zOMF5TCGI
w8MHDIFGjojxy1L/LS6duk2dBHBBWgpUp7yxON9qvgCOLF+jpB6RCLmkjuv8dIYz
FAx187hBWQatuE25d5F2ZrM67gMeZiHU/u9w7k/7eNf8hGENBJ6chCCwj3krd8G8
Ll+gNIl4vLxYKS493mDdNwP7EwKBgQDCaubvwLN16irYuMl3gW75S/BMJ2Aars9/
SH6GFcIIAUuLL8nTz73DfRkb0VFGdCB9330Ix0nY0GyK245QLs1L04Gmju7ku1k0
tB2IazVdUI8FjjNU0P6DXBai7KHIJXdNEPuOOGUKwB3iUgaaj22q4SFqhlwogZF7
1qlf8ohPcQKBgF5PINRv1BsyqAiAKsAKCakbPKLBdaATUA/AFNYDg4xIvHbA9qgX
T89U/Bf6nTtJcwGv2wrx5LjRw+WihuzSY2i+AvIKEaA6CN1ZhpITrTZ4rCh7K5gU
4uq5AzXEtyGNwACPOxE+9hkxtQUw1mOO9z7FZp8XLhUxYDWuFQDCYQqlAoGAKGLo
ojlXjlEcoXSRdV/P272op0kur5xMwlYe4l+2tM8AEGPW+0cWVnuwMZUj2wzYiw1X
/fDYKE/znEzLnWB7iRrgvebHPYCloUshL2uF5GKNs0u84gugM0137lRVrywJQlsa
xop0gu0xyAfeE1FkKLEnredHUarIu/71pFbPdiECgYAGo3gCD1ZfLamzuIkz7ymb
chnK8yEbvEdmtSwNWD/Eg9ZEwTjX9+O9oL2WuxjD/7HZZFEvRE3gYlBYavC8+d24
B7WYu/y4XIIdq8dHJ/ZVpvEZtl/fLzu8TbA3KHU6fq81+bhn+LoEs5b/GbWlAcMA
cqGmcX30kwvO8JZS6QoOjA==
-----END PRIVATE KEY-----`)
	rsaCertPEM = []byte(`-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUcOcw5lcrr85nqm/zyYEiupF+l60wDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMjA4MTkyMTA0MzNaFw0yMjA5
MTgyMTA0MzNaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCv3j2mB1ZvxjW3ncCTbCWB0u0xP2vdlAsKBZ7iym3U
3yTgXuVp+CbBrUMU0xYtFEqCre3q81kc53GY/aatE4a/Nq+HTpTarkmPh/txOL8V
dMESwgdlQEhqEmVqFuyBPDHp0MWJsX/4SAhWN3uee4zOngvcP5c+DE00o37SgSRL
bBP2Etdmsvm+dPqFQ+iPUKkgBxYYJFVMOyxUtg6UUtXLJ+ypjLkx1dVt5zTakFT3
GuM9D9rsyJ3QbtD4H/u8IVV7OTfI0p5Fg6lhdyKnmw8CK5zIaX27MATOEb8PlreL
6GdldLBWl8bUGb4Ct+trokAmIPVzLj0zV5CvuiHbVLBjAgMBAAGjUzBRMB0GA1Ud
DgQWBBQBAKA3cIQxn8aLswhOFzHsc7N6HTAfBgNVHSMEGDAWgBQBAKA3cIQxn8aL
swhOFzHsc7N6HTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCZ
8cI3sB+GdQ+4bMwSwYCopSvX/BNrBPBYgr30ximjwbFusDPL+y9apj6twkPlgOWm
YlAtR+/GrIMX97DL5Xcnhw5QcbYqaEODOqW0e4IvwZdnZ/otutxpifEAa9kT7bLB
EJw1lXZXo7WNZzynba1NgKWmYriC61Oq8pSPWwzNGa5P35LozVkcgK8prwCWfH7r
usI/f2M2Raa7kQvwPLsutE9F/FfnCPDU3UGJRjOrrBOeTcALHTjmBRNTH5syaZSZ
XzMyMCIwwYgXuVbuHNjcfLV2Ov4ufxPN4U516x2h01uVnEzEi2Wac1uNNQf+N5ct
Q88pbalfoTDAd1mCcpMu
-----END CERTIFICATE-----
`)
	// generated with `openssl ecparam -genkey -name prime256v1 -noout -out ecdsa.key`
	ecdsaKeyPEM = []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMDaz87Hngva0Wm+QkhCJ0Nz5o958+dsyH0DzsCe6Fl6oAoGCCqGSM49
AwEHoUQDQgAEI06FHb4RKoYKcj+51w6WcN7kNI9OVSTp6H8BlljYYs2zxuIh6LQ3
hXIC6UT+IOGQBnvq86SAbnPEWMLowtQc/Q==
-----END EC PRIVATE KEY-----
`)
	// generated with `openssl genpkey -algorithm ed25519 -out ed25519.key`
	ed25519KeyPEM = []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIGf81V4UAiKXFehNALvwlSlB8ZYb/RbRUMSdTG3mSZLN
-----END PRIVATE KEY-----
`)
)
