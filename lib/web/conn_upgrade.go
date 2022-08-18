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
	"context"
	"io"
	"net"
	"net/http"

	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"
	"github.com/julienschmidt/httprouter"
)

type upgradeHandler func(ctx context.Context, conn net.Conn) error

// selectConnectionUpgradeType selects the requested upgrade type.
func (h *Handler) selectConnectionUpgradeType(r *http.Request) (string, upgradeHandler, error) {
	upgrades := r.Header.Values(constants.ConnectionUpgradeHeader)
	for _, upgradeType := range upgrades {
		switch upgradeType {
		case constants.ConnectionUpgradeTypeALPN:
			return upgradeType, h.upgradeToALPN, nil
		}
	}

	return "", nil, trace.BadParameter("unsupported upgrade types: %v", upgrades)
}

// connectionUpgrade handles connection upgrades.
func (h *Handler) connectionUpgrade(w http.ResponseWriter, r *http.Request, p httprouter.Params) (interface{}, error) {
	upgradeType, upgradeHandler, err := h.selectConnectionUpgradeType(r)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, trace.BadParameter("failed to hijack connection")
	}

	conn, _, err := hj.Hijack()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer conn.Close()

	// Since w is hijacked, there is no point returning an error for response
	// starting at this point.
	if err := writeUpgradeResponse(conn, upgradeType); err != nil {
		h.log.WithError(err).Error("Failed to write upgrade response.")
		return nil, nil
	}

	if err := upgradeHandler(r.Context(), conn); err != nil {
		h.log.WithError(err).Errorf("Failed to handle %v upgrade request.", upgradeType)
	}
	return nil, nil
}

// upgradeToALPN handles upgraded ALPN connection.
func (h *Handler) upgradeToALPN(ctx context.Context, conn net.Conn) error {
	if h.cfg.ALPNHandler == nil {
		return trace.BadParameter("missing ALPNHandler")
	}

	err := h.cfg.ALPNHandler.HandleConnection(ctx, conn)
	if err != nil && !utils.IsOKNetworkError(err) {
		return trace.Wrap(err)
	}
	return nil
}

func writeUpgradeResponse(w io.Writer, upgradeType string) error {
	header := make(http.Header)
	header.Add("Upgrade", upgradeType)
	response := &http.Response{
		Status:     http.StatusText(http.StatusSwitchingProtocols),
		StatusCode: http.StatusSwitchingProtocols,
		Header:     header,
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	return response.Write(w)
}
