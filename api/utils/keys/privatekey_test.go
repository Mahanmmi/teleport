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

// generated with `openssl req -x509 -out rsa.crt -keyout rsa.key -newkey rsa:2048 -nodes -sha256`
var (
	rsaKeyPEM = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA3oJ7CEGLoQ+JdbTY5j//tgZC+kG5dUIAnMecOy4OXGUp2dYv
KC/ZCZkc0SQDaiTS35STaguJbrEBPvu34kXb0HDFP+GFULso/DqajwncOIq+/Rlp
M6JJFrPtl26aP4km3HdKApoUG3CzjFdAHSMm04PGWAqdWoHnd/910w0Ve8QoAjdP
JcpfDnheilXeqz/+zbSmXB0CVTRz6JH8L8R/Enk07pCHh0kfT3LYQDhImtJZUWTr
ePmamP8XoV9z+naYZ+qeB+KamNfuzm7ZOLQoYpAhpcN+3JPaPijGOmWhe86ASjxx
TMGSlEeLMCO++2K5gwNzOEw8cpIv8A9hTgswUwIDAQABAoIBAHAybwNMubFu+ism
E7CWWMRaB+/UsEVWEKT9aePVZ1xjjmTPQVwMNG5IjGVQuYAOLV6btnFke9oa2rv9
hU1NWHeURYHen7CDjzkP+9tgZ3EDVSaeZ5Onox8Vfxo6pQCgkb3dUK5bLwRfIcoE
PMn0baF98sd2Ir3+fs7dO3Y+RLTw1STWEQPc38YDjC50vAlqaeVqiuq5Z6tdQI20
FJvD4IA9vEHGdaQCVnHqYYmLj1ScUqApU8tqSy//diycboPOgbyleI1Tc99Kr1u0
YrEhEWYpEq+RPeWDB3Pd+gkv2x0pu9YurPbx5BMpTlDDI/SEaHYUf5tPMDGscxj9
rw9crQECgYEA+ZIw+U4hohRDrU8fny/adhFOJHXwlllGX2gvZZ/3kNMZyZ2qB0vg
euW3KZQb22HjSV1Hb3fYmntZ8hAm0CYHiSoYIxdwTU2TM4TnTxkzwUuzJYYWeW6R
sFi3rim1oJ0r0YzM7PnT2jxY2VrVwXejEQSqBy7i6ZOoik/lXR9xK8ECgYEA5D3U
7XKIl4XG60EvcUbyi9n5ZjPLMluMkHVBfdHYhIyzAMk/r7NgIfx/RvWC0Rev9oZf
68zWZPISe8Hhvk50AWmNFz9e4RTN6A+CETcRsnivlQpHorLunmqVEh9EjaLeyjH5
Ypjv9XEhNSvq9yZB+30eLVX5cte/6rc6XJSFMRMCgYA/qO+/GBPyMPMWaSFqzJ0Q
Etf46vCkmT8fJQc6B/TxRzfDuujdFZi8II55F6OHcU+1rgqDv3FL7n0CBuavn5O6
hDdF9DucLFaJBLSv84DFJJcc0jg3X2HgNrEbxt3ii1TbDexT4mIMv+n1/3qY7/hz
ZdotHOOaqySJq1mZSGTowQKBgQCGGG3JM8lcfJRqE1o0S2KlF+OXUEbJx0/Gb52S
tn9nIOLqS1LHf7OzRA3jOsso3ancRQaGG0q69B4356khjiZJziG+ztSHmRmAhdv9
EUWsfYtrHScJR+c525TJmOVF8bLDSKkkbIZOxbCk9LCPlEKf5tqb+C8ecfOniw8W
5Yt7UQKBgQC5Ddp8WsjeMQw1lVot5dmov+XI3xGjU1VOHaPLROfEcGcT/hECi7m2
RqAkszaiBY9zOeBabziETI0Yz2HJ8yb9EOvEU5XDLQZxUlyLzLX/iPB0CMhGZamS
uqFtQXxHcN6SKMemOGegGcmvDezbq1VuIQwlC7dInHjdrMUA6R/9GA==
-----END RSA PRIVATE KEY-----
`)
	rsaCertPEM = []byte(`-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUAJcFwTvUhqVPtOQz9LoZMFjdHNAwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMjA4MTkyMDAwMTlaFw0yMjA5
MTgyMDAwMTlaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCwOAugKWySntuMVe4i9r7be1YVedMFV+TJYBm+bE79
CoQWT6/yipBngpcqBCSalcvemFj1GN2MmBZPO83ixEnj2H5PUqAyVYc/JLks+rvD
IF9vDwkPTUxV1RJ7pBZrPQwILTAFCsMmtUyamozTxKsaDbUpS7SJLsBJJuQ2eqNE
F9+4B7A9R9KI4MqpNJC4Aq8H7xogp4w11+IB97RtUeV+Oy4Xf31oW7Dg3vAHJwYC
SbrxQIYBwviTZiimSLOyXKUnQ7VDA03eKRxiaQSmPDYRaGGgTaFBGLNcGl+dCbbs
Y51/98CxQfGDP3viYen2VRbLLLyEoWRGxdrzP69Qm4OnAgMBAAGjUzBRMB0GA1Ud
DgQWBBQZNFypAQe0TMQuGb1wM7OZ9Isq/TAfBgNVHSMEGDAWgBQZNFypAQe0TMQu
Gb1wM7OZ9Isq/TAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB/
8lAIuDPGYG9C1soX31X796/6hDXHlw4g3x7aR1B/labMA4VOX0DPZHcff+jvcf/6
KRrSRz434bv2TnNRV5uZnemGQG62D2d8MOvLUIYdhBb/+4WQD1fvoAVXd9CVmUsS
/1WxidR2yECtjVNnmun/8FkGvO3IwANVddTw/6GdhFPEKweaY0ovcfhMA9ViNTRV
ePteZZ+zzLgM96jv128miEKaQFO3GVCMFjMiHpBfkRV/cS8UqEC3x6wqRCZDqgJ3
aUtIricT34Q7tUlIUM4hn3e9FMfqP03a+W8JItkCrUe1Db7BvAgA+9bHK+o18r1D
mv1iYi4eRlpXnOD6LJIG
-----END CERTIFICATE-----`)
)
