// Copyright 2021 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package apiserver

import (
	"net"
	"path/filepath"

	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/url"

	api "github.com/gravitational/teleport/lib/teleterm/api/protogen/golang/v1"
	"github.com/gravitational/teleport/lib/teleterm/apiserver/handler"

	"github.com/gravitational/trace"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// New creates an instance of API Server
func New(cfg Config) (*APIServer, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	serviceHandler, err := handler.New(
		handler.Config{
			DaemonService: cfg.Daemon,
		},
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	ls, err := newListener(cfg.HostAddr)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	keyPair, err := LoadKeyPair(cfg.CertsDir)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	grpcServer := grpc.NewServer(grpc.Creds(keyPair), grpc.ChainUnaryInterceptor(
		withErrorHandling(cfg.Log),
	))

	api.RegisterTerminalServiceServer(grpcServer, serviceHandler)

	return &APIServer{cfg, ls, grpcServer}, nil
}

// Serve starts accepting incoming connections
func (s *APIServer) Serve() error {
	return s.grpcServer.Serve(s.ls)
}

// Stop stops the server and closes all listeners
func (s *APIServer) Stop() {
	s.grpcServer.GracefulStop()
}

func newListener(hostAddr string) (net.Listener, error) {
	uri, err := url.Parse(hostAddr)

	if err != nil {
		return nil, trace.BadParameter("invalid host address: %s", hostAddr)
	}

	lis, err := net.Listen(uri.Scheme, getAddrByScheme(uri))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return lis, nil
}

func getAddrByScheme(uri *url.URL) string {
	if uri.Scheme == "unix" {
		return uri.Path
	}
	return uri.Host
}

// Server is a combination of the underlying grpc.Server and its RuntimeOpts.
type APIServer struct {
	Config
	// ls is the server listener
	ls net.Listener
	// grpc is an instance of grpc server
	grpcServer *grpc.Server
}

func LoadKeyPair(certsDir string) (credentials.TransportCredentials, error) {
	certificate, err := tls.LoadX509KeyPair(
		filepath.Join(certsDir, "server.crt"), filepath.Join(certsDir, "server.key"))
	if err != nil {
		return nil, trace.Wrap(err, "failed to load server certificates")
	}

	caCert, err := ioutil.ReadFile(filepath.Join(certsDir, "ca.crt"))

	if err != nil {
		return nil, trace.Wrap(err, "failed to read CA file")
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, trace.Wrap(err, "failed to add CA file")
	}

	tlsConfig := &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    caPool,
	}
	return credentials.NewTLS(tlsConfig), nil
}
