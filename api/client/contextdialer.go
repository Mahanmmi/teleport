/*
Copyright 2020 Gravitational, Inc.

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
	"net"
	"time"

	"github.com/gravitational/teleport/api/client/proxy"
	"github.com/gravitational/teleport/api/client/webclient"
	"github.com/gravitational/teleport/api/constants"
	tracessh "github.com/gravitational/teleport/api/observability/tracing/ssh"
	"github.com/gravitational/teleport/api/utils/sshutils"

	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"
)

// ContextDialer represents network dialer interface that uses context
type ContextDialer interface {
	// DialContext is a function that dials the specified address
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// ContextDialerFunc is a function wrapper that implements the ContextDialer interface.
type ContextDialerFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// DialContext is a function that dials to the specified address
func (f ContextDialerFunc) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return f(ctx, network, addr)
}

// newDirectDialer makes a new dialer to connect directly to an Auth server.
func newDirectDialer(keepAlivePeriod, dialTimeout time.Duration) ContextDialer {
	return &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: keepAlivePeriod,
	}
}

// NewDialer makes a new dialer that connects to an Auth server either
// directly, via HTTP connection upgrade, or via an HTTP proxy, depending on
// the environment.
func NewDialer(keepAlivePeriod, dialTimeout time.Duration, tlsConfig *tls.Config) ContextDialer {
	return ContextDialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := newDirectDialer(keepAlivePeriod, dialTimeout)

		if isHTTPConnUpgradeRequired(addr, tlsConfig) {
			dialer = newHTTPConnUpgradeDialer(tlsConfig.InsecureSkipVerify)
		}

		if proxyURL := proxy.GetProxyURL(addr); proxyURL != nil {
			return DialProxyWithDialer(ctx, proxyURL, addr, dialer)
		}

		return dialer.DialContext(ctx, network, addr)
	})
}

// NewProxyDialer makes a dialer to connect to an Auth server through the SSH reverse tunnel on the proxy.
// The dialer will ping the web client to discover the tunnel proxy address on each dial.
func NewProxyDialer(ssh ssh.ClientConfig, keepAlivePeriod, dialTimeout time.Duration, discoveryAddr string, insecure bool) ContextDialer {
	dialer := newTunnelDialer(ssh, keepAlivePeriod, dialTimeout)
	return ContextDialerFunc(func(ctx context.Context, network, _ string) (conn net.Conn, err error) {
		tunnelAddr, err := webclient.GetTunnelAddr(
			&webclient.Config{Context: ctx, ProxyAddr: discoveryAddr, Insecure: insecure})
		if err != nil {
			return nil, trace.Wrap(err)
		}

		conn, err = dialer.DialContext(ctx, network, tunnelAddr)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return conn, nil
	})
}

// newTunnelDialer makes a dialer to connect to an Auth server through the SSH reverse tunnel on the proxy.
func newTunnelDialer(ssh ssh.ClientConfig, keepAlivePeriod, dialTimeout time.Duration) ContextDialer {
	dialer := newDirectDialer(keepAlivePeriod, dialTimeout)
	return ContextDialerFunc(func(ctx context.Context, network, addr string) (conn net.Conn, err error) {
		conn, err = dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		sconn, err := sshConnect(ctx, conn, ssh, dialTimeout, addr)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return sconn, nil
	})
}

// newTLSRoutingTunnelDialer makes a reverse tunnel TLS Routing dialer to connect to an Auth server
// through the SSH reverse tunnel on the proxy.
func newTLSRoutingTunnelDialer(ssh ssh.ClientConfig, keepAlivePeriod, dialTimeout time.Duration, discoveryAddr string, insecure bool) ContextDialer {
	return ContextDialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		tunnelAddr, err := webclient.GetTunnelAddr(
			&webclient.Config{Context: ctx, ProxyAddr: discoveryAddr, Insecure: insecure})
		if err != nil {
			return nil, trace.Wrap(err)
		}

		host, _, err := webclient.ParseHostPort(tunnelAddr)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		tlsDialer, err := NewTLSRoutingDialer(TLSRoutingDialerConfig{
			KeepAlivePeriod: keepAlivePeriod,
			DialTimeout:     dialTimeout,
			Addr:            tunnelAddr,
			TLSConfig: &tls.Config{
				NextProtos:         []string{constants.ALPNSNIProtocolReverseTunnel},
				InsecureSkipVerify: insecure,
				ServerName:         host,
			},
		})
		if err != nil {
			return nil, trace.Wrap(err)
		}

		tlsConn, err := tlsDialer.DialContext(ctx, network, tunnelAddr)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		sconn, err := sshConnect(ctx, tlsConn, ssh, dialTimeout, tunnelAddr)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return sconn, nil
	})
}

// sshConnect upgrades the underling connection to ssh and connects to the Auth service.
func sshConnect(ctx context.Context, conn net.Conn, ssh ssh.ClientConfig, dialTimeout time.Duration, addr string) (net.Conn, error) {
	ssh.Timeout = dialTimeout
	sconn, err := tracessh.NewClientConnWithDeadline(ctx, conn, addr, &ssh)
	if err != nil {
		return nil, trace.NewAggregate(err, conn.Close())
	}

	// Build a net.Conn over the tunnel. Make this an exclusive connection:
	// close the net.Conn as well as the channel upon close.
	conn, _, err = sshutils.ConnectProxyTransport(sconn.Conn, &sshutils.DialReq{
		Address: constants.RemoteAuthServer,
	}, true)
	if err != nil {
		return nil, trace.NewAggregate(err, sconn.Close())
	}
	return conn, nil
}

// TLSRoutingDialerConfig is the config for TLSRoutingDialer.
type TLSRoutingDialerConfig struct {
	// KeepAlivePeriod is the optional period between keep alives.
	KeepAlivePeriod time.Duration
	// DialTimeout is the optional period of how long to attempt dialing before
	// timing out.
	DialTimeout time.Duration
	// TLSConfig is the default TLS config used for ALPN connection test and
	// TLS handshake.
	TLSConfig *tls.Config
	// Addr is the default host address used for ALPN connection test.
	Addr string
}

// CheckAndSetDefaults validates the config and set defaults.
func (c *TLSRoutingDialerConfig) CheckAndSetDefaults() error {
	if c.Addr == "" {
		return trace.BadParameter("missing address")
	}
	if c.TLSConfig == nil {
		return trace.BadParameter("missing TLS config")
	}
	return nil
}

// TLSRoutingDialer is a ContextDialer used for making TLS routing connections.
type TLSRoutingDialer struct {
	TLSRoutingDialerConfig

	netDialer ContextDialer
}

// NewTLSRoutingDialer creates a new TLSRoutingDialer.
func NewTLSRoutingDialer(config TLSRoutingDialerConfig) (*TLSRoutingDialer, error) {
	if err := config.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	// Do an ALPN connection test to decide if HTTP connection upgrade is required.
	var netDialer ContextDialer
	if isHTTPConnUpgradeRequired(config.Addr, config.TLSConfig) {
		netDialer = newHTTPConnUpgradeDialer(config.TLSConfig.InsecureSkipVerify)
	} else {
		netDialer = newDirectDialer(config.KeepAlivePeriod, config.DialTimeout)
	}

	return &TLSRoutingDialer{
		TLSRoutingDialerConfig: config,
		netDialer:              netDialer,
	}, nil
}

// DialContext implements ContextDialer.
func (d *TLSRoutingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := d.netDialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	tlsConn := tls.Client(conn, d.TLSConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		defer conn.Close()
		return nil, trace.Wrap(err)
	}

	return tlsConn, nil
}
