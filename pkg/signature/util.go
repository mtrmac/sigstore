//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package signature

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"

	sigpayload "github.com/sigstore/sigstore/pkg/signature/payload"
)

// SignImage signs a container manifest with manifestDigest using the specified signer object, claiming it to be claimedIdentity
func SignImage(signer SignerVerifier, claimedIdentity name.Reference, manifestDigest string, optionalAnnotations map[string]interface{}) (payload, signature []byte, err error) {
	imgPayload := sigpayload.Cosign{
		ClaimedIdentity: claimedIdentity,
		ImageDigest:     manifestDigest,
		Annotations:     optionalAnnotations,
	}
	payload, err = json.Marshal(imgPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal payload to JSON: %w", err)
	}
	signature, err = signer.SignMessage(bytes.NewReader(payload))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign payload: %w", err)
	}
	return payload, signature, nil
}
