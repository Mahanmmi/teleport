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
	"strconv"

	"github.com/go-piv/piv-go/piv"
	"github.com/gravitational/trace"
)

const (
	// PIVCardTypeYubikey is the PIV card type assigned to yubikeys.
	PIVCardTypeYubikey = "yubikey"
)

// GeneratePIVPrivateKey generates a new PrivateKey on the given slot of
// the card identified by cardType and uniqueCardID. If a cardID isn't
// specified, then the first PIV key found for the given cardType will be used.
func GeneratePIVPrivateKey(cardType, uniqueCardID string) (PrivateKey, error) {
	switch cardType {
	case PIVCardTypeYubikey:
		return GenerateYubikeyPrivateKey(uniqueCardID)
	default:
		return nil, trace.BadParameter("PIV device %q not supported", cardType)
	}
}

// ParsePIVSlot parses a piv.Slot from slotName, like "9a".
func ParsePIVSlot(slotName string) (piv.Slot, error) {
	key, err := strconv.ParseUint(slotName, 16, 32)
	if err != nil {
		return piv.Slot{}, trace.Wrap(err)
	}

	switch uint32(key) {
	case piv.SlotAuthentication.Key:
		return piv.SlotAuthentication, nil
	case piv.SlotSignature.Key:
		return piv.SlotSignature, nil
	case piv.SlotCardAuthentication.Key:
		return piv.SlotCardAuthentication, nil
	case piv.SlotKeyManagement.Key:
		return piv.SlotKeyManagement, nil
	}

	retiredSlot, ok := piv.RetiredKeyManagementSlot(uint32(key))
	if !ok {
		return piv.Slot{}, trace.BadParameter("slot %q does not exist", slotName)
	}
	return retiredSlot, nil
}
