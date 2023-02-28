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
	"testing"

	"github.com/go-test/deep"
	"github.com/google/go-containerregistry/pkg/name"
	sigpayload "github.com/sigstore/sigstore/pkg/signature/payload"
)

const validDigest = "sha256:d34db33fd34db33fd34db33fd34db33fd34db33fd34db33fd34db33fd34db33f"

func mustParseDigest(t *testing.T, digestStr string) name.Digest {
	t.Helper()
	digest, err := name.NewDigest(digestStr)
	if err != nil {
		t.Fatalf("could not parse digest %q: %v", digestStr, err)
	}
	return digest
}

func TestProviderRoundtrip(t *testing.T) {
	ecdsaSV, _, err := NewDefaultECDSASignerVerifier()
	if err != nil {
		t.Fatalf("Could not generate ecdsa SignerVerifier for test: %v", err)
	}
	rsaSV, _, err := NewDefaultRSAPSSSignerVerifier()
	if err != nil {
		t.Fatalf("Could not generate rsa SignerVerifier for test: %v", err)
	}

	testCases := []struct {
		desc   string
		sv     SignerVerifier
		digest name.Digest
		claims map[string]interface{}
	}{
		{
			desc:   "ECDSA",
			sv:     ecdsaSV,
			digest: mustParseDigest(t, "example.com/ecdsa@"+validDigest),
			claims: map[string]interface{}{
				"creator":  "ECDSA",
				"optional": "extras",
			},
		},
		{
			desc:   "RSA",
			sv:     rsaSV,
			digest: mustParseDigest(t, "example.com/rsa@"+validDigest),
			claims: map[string]interface{}{
				"creator":            "RSA",
				"Floaty McFloatface": 6.022e23,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			payload, sig, err := SignImage(tc.sv, tc.digest, tc.claims)
			if err != nil {
				t.Fatalf("SignImage returned error: %v", err)
			}

			// This is not a paranoid enough signature verification implementation, but just enough for a smoke test.
			if err := tc.sv.VerifySignature(bytes.NewReader(sig), bytes.NewReader(payload)); err != nil {
				t.Fatalf("Cryptographic signature verification failed: %v", err)
			}
			var raw struct { // not payload.Cosign, which explicitly refuses to UnmarshalJSON
				Critical sigpayload.Critical
				Optional map[string]interface{}
			}
			if err := json.Unmarshal(payload, &raw); err != nil {
				t.Fatalf("Parsing payload verification failed: %v", err)
			}
			if tc.digest.Repository.Name() != raw.Critical.Identity.DockerReference {
				t.Errorf("got identity %q, wanted %q", raw.Critical.Identity.DockerReference, tc.digest.Repository.Name())
			}
			if tc.digest.DigestStr() != raw.Critical.Image.DockerManifestDigest {
				t.Errorf("got manifest digest %q, wanted %q", raw.Critical.Image.DockerManifestDigest, tc.digest.DigestStr())
			}
			if diff := deep.Equal(tc.claims, raw.Optional); diff != nil {
				t.Errorf("claims were altered during the roundtrip: %v", diff)
			}
		})
	}
}
