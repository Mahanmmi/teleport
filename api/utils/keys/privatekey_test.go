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
		expectType  interface{}
	}{
		{
			desc:   "invalid PEM",
			keyPEM: []byte(`non-pem data`),
			assertError: func(t require.TestingT, err error, i ...interface{}) {
				require.Error(t, err)
				require.True(t, trace.IsBadParameter(err))
			},
		},
		{
			desc: "invalid type",
			keyPEM: []byte(`-----BEGIN INVALID KEY-----
-----END INVALID KEY-----
`),
			assertError: func(t require.TestingT, err error, i ...interface{}) {
				require.Error(t, err)
				require.True(t, trace.IsBadParameter(err))
			},
		},
		{
			desc:       "rsa key",
			keyPEM:     rsaPEM,
			expectType: &RSAPrivateKey{},
		},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			priv, err := ParsePrivateKey(tt.keyPEM)
			if tt.assertError != nil {
				tt.assertError(t, err)
				return
			}
			require.NoError(t, err)
			require.IsType(t, tt.expectType, priv)
		})
	}
}

// TestX509KeyPair tests that X509KeyPair returns the same value as tls.X509KeyPair
func TestX509KeyPair(t *testing.T) {
	expectCert, err := tls.X509KeyPair(rsaCert, rsaPEM)
	require.NoError(t, err)

	tlsCert, err := X509KeyPair(rsaCert, rsaPEM)
	require.NoError(t, err)

	require.Equal(t, expectCert, tlsCert)
}

var (
	rsaPEM = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAzkUVoJ4rn2XAi2HJeBIIxlsdMPGzLroJub9eHAVspAueDJLS
gqQduHTog01R9MAARoWUwbQLN0DIbJFK70UrwETXbuREcGzqFvWlODLZ/pMWQWj+
HhZNZbgZBKI7wCXsDa25GNzeYCeTvWr6S+lBhLu2eSGYUJgTyMrEy2Vgbf3HiRDp
u2WXs/3Mjpdm/lFGuXOoAO7BmkRwthWLROMhOo9vHesNlPiX4SayWFqgb7ETlW74
ZhcuW/AH0T9qZ83Vn0qmzg5vonHGx72SN4yKv2bCI2QFZXKEf8sRMMD1drqxNDZ7
vkxgzvJcktg6YEpXiDXvpB/VPXJ7tr8aCfi3ZQIDAQABAoIBAE1Vk207wAksAgt/
5yQwRr/vizs9czuSnnDYsbT5x6idfm0iYvB+DXKJyl7oD1Ee5zuJe6NAGHBnxn0F
4D1jBqs4ZDj8NjicbQucn4w5bIfIp7BwZ83p+KypYB/fn11EGoNqXZpXvLv6Oqbq
w9rQIjNcmWZC1TNqQQioFS5Y3NV/gw5uYCRXZlSLMsRCvcX2+LN2EP76ZbkpIVpT
CidC2TxwFPPbyMsG774Olfz4U2IDgX1mO+milF7RIa/vPADSeHAX6tJHmZ13GsyP
0GAdPbFa0Ls/uykeGi1uGPFkdkNEqbWlDf1Z9IG0dr/ck2eh8G2X8E+VFgzsKp4k
WtH9nGECgYEA53lFodLiKQjQR7IoUmGp+P6qnrDwOdU1RfT9jse35xOb9tYvZs3X
kUXU+MEGAMW1Pvmo1v9xOjZbdFYB9I/tIYTSyjYQNaFjgJMPMLSx2qjMzhFXAY5f
8t20/CBt2V1q46aa8tR2ll//QvY4mqvJUaaB0pkuasFbKMXJcGKdvdkCgYEA5CAo
UI8NVA9GqAJfs7hkGHQwpX1X1+JpFhF4dZKsV40NReqaK0vd/mWTYjlMOPO6oolr
PoCDUlQYU6poIDtEnfJ6KkYuLMgxZKnS2OlDthKoZJe9aUTCP1RhTVHyyABRXbGg
tNMKFYkZ38C9+JM+X5T0eKZTHeK+wjiZd55+sm0CgYAmyp0PxI6gP9jf2wyE2dcp
YkxnsdFgb8mwwqDnl7LLJ+8gS76/5Mk2kFRjp72AzaFVP3O7LC3miouDEJLdUG12
C5NjzfGjezt4payLBg00Tsub0S4alaigw+T7x9eA8PXj1tzqyw5gnw/hQfA0g4uG
gngJOiCcRXEogRUEH5K96QKBgFUnB8ViUHhTJ22pTS3Zo0tZe5saWYLVGaLKLKu+
byRTG2RAuQF2VUwTgFtGxgPwPndTUjvHXr2JdHcugaWeWfOXQjCrd6rxozZPCcw7
7jF1b3P1DBfSOavIBHYHI9ex/q05k6JLsFTvkz/pQ0AZPkwRXtv2QcpDDC+VTvvO
pr5VAoGBAJBhNjs9wAu+ZoPcMZcjIXT/BAj2tQYiHoRnNpvQjDYbQueUBeI0Ry8d
5QnKS2k9D278P6BiDBz1c+fS8UErOxY6CS0pi4x3fjMliPwXj/w7AzjlXgDBhRcp
90Ns/9SamlBo9j8ETm9g9D3EVir9zF5XvoR13OdN9gabGy1GuubT
-----END RSA PRIVATE KEY-----`)
	rsaCert = []byte(`-----BEGIN CERTIFICATE-----
MIIDyzCCArOgAwIBAgIQD3MiJ2Au8PicJpCNFbvcETANBgkqhkiG9w0BAQsFADBe
MRQwEgYDVQQKEwtleGFtcGxlLmNvbTEUMBIGA1UEAxMLZXhhbXBsZS5jb20xMDAu
BgNVBAUTJzIwNTIxNzE3NzMzMTIxNzQ2ODMyNjA5NjAxODEwODc0NTAzMjg1ODAe
Fw0yMTAyMTcyMDI3MjFaFw0yMTAyMTgwODI4MjFaMIGCMRUwEwYDVQQHEwxhY2Nl
c3MtYWRtaW4xCTAHBgNVBAkTADEYMBYGA1UEEQwPeyJsb2dpbnMiOm51bGx9MRUw
EwYDVQQKEwxhY2Nlc3MtYWRtaW4xFTATBgNVBAMTDGFjY2Vzcy1hZG1pbjEWMBQG
BSvODwEHEwtleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAM5FFaCeK59lwIthyXgSCMZbHTDxsy66Cbm/XhwFbKQLngyS0oKkHbh06INN
UfTAAEaFlMG0CzdAyGyRSu9FK8BE127kRHBs6hb1pTgy2f6TFkFo/h4WTWW4GQSi
O8Al7A2tuRjc3mAnk71q+kvpQYS7tnkhmFCYE8jKxMtlYG39x4kQ6btll7P9zI6X
Zv5RRrlzqADuwZpEcLYVi0TjITqPbx3rDZT4l+EmslhaoG+xE5Vu+GYXLlvwB9E/
amfN1Z9Kps4Ob6Jxxse9kjeMir9mwiNkBWVyhH/LETDA9Xa6sTQ2e75MYM7yXJLY
OmBKV4g176Qf1T1ye7a/Ggn4t2UCAwEAAaNgMF4wDgYDVR0PAQH/BAQDAgWgMB0G
A1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB8GA1Ud
IwQYMBaAFJWqMooE05nf263F341pOO+mPMSqMA0GCSqGSIb3DQEBCwUAA4IBAQCK
s0yPzkSuCY/LFeHJoJeNJ1SR+EKbk4zoAnD0nbbIsd2quyYIiojshlfehhuZE+8P
bzpUNG2aYKq+8lb0NO+OdZW7kBEDWq7ZwC8OG8oMDrX385fLcicm7GfbGCmZ6286
m1gfG9yqEte7pxv3yWM+7X2bzEjCBds4feahuKPNxOAOSfLUZiTpmOVlRzrpRIhu
2XxiuH+E8n4AP8jf/9bGvKd8PyHohtHVf8HWuKLZxWznQhoKkcfmUmlz5q8ci4Bq
WQdM2NXAMABGAofGrVklPIiraUoHzr0Xxpia4vQwRewYXv8bCPHW+8g8vGBGvoG2
gtLit9DL5DR5ac/CRGJt
-----END CERTIFICATE-----`)
)
