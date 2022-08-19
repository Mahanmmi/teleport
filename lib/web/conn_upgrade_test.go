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

package web

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
)

func TestWriteUpgradeResponse(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, writeUpgradeResponse(&buf, "custom"))
	require.Equal(t, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: custom\r\n\r\n", buf.String())
}

func TestHandlerConnectionUpgrade(t *testing.T) {
	t.Parallel()

	cfg := Config{
		ALPNHandler: func(_ context.Context, conn net.Conn) error {
			conn.Write([]byte("hello@"))
			return nil
		},
	}
	h := &Handler{
		cfg:   cfg,
		log:   newPackageLogger(),
		clock: clockwork.NewRealClock(),
	}

	t.Run("unsupported type", func(t *testing.T) {
		r, err := http.NewRequest("GET", "http://localhost/"+constants.ConnectionUpgradeWebAPI, nil)
		require.NoError(t, err)
		r.Header.Add(constants.ConnectionUpgradeHeader, "unsupported-protocol")

		_, err = h.connectionUpgrade(httptest.NewRecorder(), r, nil)
		require.True(t, trace.IsBadParameter(err))
	})

	t.Run("upgraded to ALPN", func(t *testing.T) {
		serverConn, clientConn := net.Pipe()
		defer serverConn.Close()
		defer clientConn.Close()

		r, err := http.NewRequest("GET", "http://localhost/"+constants.ConnectionUpgradeWebAPI, nil)
		require.NoError(t, err)
		r.Header.Add(constants.ConnectionUpgradeHeader, constants.ConnectionUpgradeTypeALPN)

		go func() {
			// serverConn will be hijacked.
			w := newResponseWriterHijacker(nil, serverConn)
			_, err = h.connectionUpgrade(w, r, nil)
			require.NoError(t, err)
		}()

		// Verify clientConn receives http.StatusSwitchingProtocols.
		clientConnReader := bufio.NewReader(clientConn)
		response, err := http.ReadResponse(clientConnReader, r)
		require.NoError(t, err)
		require.Equal(t, http.StatusSwitchingProtocols, response.StatusCode)

		// Verify clientConn receives data sent by Config.ALPNHandler.
		receive, err := clientConnReader.ReadString(byte('@'))
		require.NoError(t, err)
		require.Equal(t, "hello@", receive)
	})
}

// responseWriterHijacker is a mock http.ResponseWriter that also serves a
// net.Conn for http.Hijacker.
type responseWriterHijacker struct {
	http.ResponseWriter
	conn net.Conn
}

func newResponseWriterHijacker(w http.ResponseWriter, conn net.Conn) *responseWriterHijacker {
	if w == nil {
		w = httptest.NewRecorder()
	}
	return &responseWriterHijacker{
		ResponseWriter: w,
		conn:           conn,
	}
}

func (h responseWriterHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return h.conn, nil, nil
}
