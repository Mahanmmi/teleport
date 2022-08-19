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

package client

import (
	"context"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/constants"
	"github.com/gravitational/trace"
	"github.com/gravitational/trace/trail"
)

// HardwareKeyServiceClient is a client for the HardwareKeyService, which runs on both the
// auth and proxy.
type HardwareKeyServiceClient struct {
	grpcClient proto.HardwareKeyServiceClient
}

// NewHardwareKeyServiceClient returns a new HardwareKeyServiceClient wrapping the given grpc
// client.
func NewHardwareKeyServiceClient(grpcClient proto.HardwareKeyServiceClient) *HardwareKeyServiceClient {
	return &HardwareKeyServiceClient{
		grpcClient: grpcClient,
	}
}

// AttestHardwarePrivateKey attests a hardware private key so that it
// will be trusted by the Auth server in subsequent calls.
func (c *HardwareKeyServiceClient) AttestHardwarePrivateKey(ctx context.Context, req *proto.AttestHardwarePrivateKeyRequest) error {
	_, err := c.grpcClient.AttestHardwarePrivateKey(ctx, req)
	return trail.FromGRPC(err)
}

// GetPrivateKeyPolicy gets the private key policy enforced for the current user.
func (c *HardwareKeyServiceClient) GetPrivateKeyPolicy(ctx context.Context) (constants.PrivateKeyPolicy, error) {
	resp, err := c.grpcClient.GetPrivateKeyPolicy(ctx, &proto.GetPrivateKeyPolicyRequest{})
	if err != nil {
		return "", trail.FromGRPC(err)
	}
	var policy constants.PrivateKeyPolicy
	switch resp.GetPolicy() {
	case proto.PrivateKeyPolicy_PRIVATE_KEY_POLICY_NONE:
		policy = constants.PrivateKeyPolicyNone
	case proto.PrivateKeyPolicy_PRIVATE_KEY_POLICY_HARDWARE_KEY:
		policy = constants.PrivateKeyPolicyHardwareKey
	case proto.PrivateKeyPolicy_PRIVATE_KEY_POLICY_HARDWARE_KEY_TOUCH:
		policy = constants.PrivateKeyPolicyHardwareKeyTouch
	default:
		return "", trace.BadParameter("unknown private key policy %q", resp.GetPolicy())
	}
	return policy, nil
}
