/*
Copyright 2021 Gravitational, Inc.

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

package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"time"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/client/terminal"
	"github.com/gravitational/teleport/lib/kube/proxy/streamproto"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gorilla/websocket"
	"github.com/gravitational/trace"
	"k8s.io/client-go/tools/remotecommand"
)

const mfaChallengeInterval = time.Second * 30

// KubeSession a joined kubernetes session from the client side.
type KubeSession struct {
	stream *streamproto.SessionStream
	term   *terminal.Terminal
	ctx    context.Context
	cancel context.CancelFunc
	meta   types.SessionTracker
}

// NewKubeSession joins a live kubernetes session.
func NewKubeSession(ctx context.Context, tc *TeleportClient, meta types.SessionTracker, kubeAddr string, tlsServer string, mode types.SessionParticipantMode, tlsConfig *tls.Config) (*KubeSession, error) {
	ctx, cancel := context.WithCancel(ctx)
	joinEndpoint := "wss://" + kubeAddr + "/api/v1/teleport/join/" + meta.GetSessionID()

	if tlsServer != "" {
		tlsConfig.ServerName = tlsServer
	}

	dialer := &websocket.Dialer{
		TLSClientConfig: tlsConfig,
	}

	ws, resp, err := dialer.Dial(joinEndpoint, nil)
	defer resp.Body.Close()
	if err != nil {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("Handshake failed with status %d\nand body: %v\n", resp.StatusCode, string(body))
		cancel()
		return nil, trace.Wrap(err)
	}

	stream, err := streamproto.NewSessionStream(ws, streamproto.ClientHandshake{Mode: mode})
	if err != nil {
		cancel()
		return nil, trace.Wrap(err)
	}

	term, err := terminal.New(tc.Stdin, tc.Stdout, tc.Stderr)
	if err != nil {
		cancel()
		return nil, trace.Wrap(err)
	}

	if term.IsAttached() {
		// Put the terminal into raw mode. Note that this must be done before
		// pipeInOut() as it may replace streams.
		term.InitRaw(true)
	}

	stdout := utils.NewSyncWriter(term.Stdout())

	go handleOutgoingResizeEvents(ctx, stream, term)
	go handleIncomingResizeEvents(stream, term)

	s := &KubeSession{stream, term, ctx, cancel, meta}
	err = s.handleMFA(ctx, tc, mode, stdout)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	s.pipeInOut(stdout, tc.EnableEscapeSequences, mode)
	return s, nil
}

func handleOutgoingResizeEvents(ctx context.Context, stream *streamproto.SessionStream, term *terminal.Terminal) {
	queue := stream.ResizeQueue()

	select {
	case <-ctx.Done():
		return
	case size := <-queue:
		if size == nil {
			return
		}

		term.Resize(int16(size.Width), int16(size.Height))
	}
}

func handleIncomingResizeEvents(stream *streamproto.SessionStream, term *terminal.Terminal) {
	events := term.Subscribe()

	for {
		event, more := <-events
		_, ok := event.(terminal.ResizeEvent)
		if ok {
			w, h, err := term.Size()
			if err != nil {
				fmt.Printf("Error attempting to fetch terminal size: %v\n\r", err)
			}

			size := remotecommand.TerminalSize{Width: uint16(w), Height: uint16(h)}
			err = stream.Resize(&size)
			if err != nil {
				fmt.Printf("Error attempting to resize terminal: %v\n\r", err)
			}
		}

		if !more {
			break
		}
	}
}

func (s *KubeSession) handleMFA(ctx context.Context, tc *TeleportClient, mode types.SessionParticipantMode, stdout io.Writer) error {
	if s.stream.MFARequired && mode == types.SessionModeratorMode {
		proxy, err := tc.ConnectToProxy(ctx)
		if err != nil {
			return trace.Wrap(err)
		}

		auth, err := proxy.ConnectToCluster(ctx, s.meta.GetClustername())
		if err != nil {
			return trace.Wrap(err)
		}

		go runPresenceTask(ctx, stdout, auth, tc, s.meta.GetSessionID())
	}

	return nil
}

// pipeInOut starts background tasks that copy input to and from the terminal.
func (s *KubeSession) pipeInOut(stdout io.Writer, enableEscapeSequences bool, mode types.SessionParticipantMode) {
	go func() {
		defer s.cancel()
		_, err := io.Copy(stdout, s.stream)
		if err != nil {
			fmt.Printf("Error while reading remote stream: %v\n\r", err.Error())
		}
	}()

	go func() {
		defer s.cancel()

		switch mode {
		case types.SessionPeerMode:
			handlePeerControls(s.term, enableEscapeSequences, s.stream)
		default:
			handleNonPeerControls(mode, s.term, func() {
				err := s.stream.ForceTerminate()
				if err != nil {
					log.Debugf("Error sending force termination request: %v", err)
					fmt.Print("\n\rError while sending force termination request\n\r")
				}
			})
		}
	}()
}

// Wait waits for the session to finish.
func (s *KubeSession) Wait() {
	<-s.ctx.Done()
}

// Close sends a close request to the other end and waits it to gracefully terminate the connection.
func (s *KubeSession) Close() error {
	if err := s.stream.Close(); err != nil {
		return trace.Wrap(err)
	}

	<-s.ctx.Done()
	return trace.Wrap(s.Detach())
}

// Detach detaches the terminal from the session. Must be called if Close is not called.
func (s *KubeSession) Detach() error {
	return trace.Wrap(s.term.Close())
}
