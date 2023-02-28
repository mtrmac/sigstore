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

// Package payload defines a container image
package payload

import (
	"encoding/json"
	"errors"

	"github.com/google/go-containerregistry/pkg/name"
)

// CosignSignatureType is the value of `critical.type` in a SimpleContainerImage payload.
const CosignSignatureType = "cosign container image signature"

// SimpleContainerImage describes the structure of a basic container image signature payload, as defined at:
// https://github.com/containers/image/blob/master/docs/containers-signature.5.md#json-data-format
//
// TO DO: This should be _very_ paranoid about missing fields, duplicated fields, and the like, when decoding.
type SimpleContainerImage struct {
	Critical Critical               `json:"critical"` // Critical data critical to correctly evaluating the validity of the signature
	Optional map[string]interface{} `json:"optional"` // Optional optional metadata about the image
}

// Critical data critical to correctly evaluating the validity of a signature
//
// TO DO: Per the simple signing payload specification, any unrecognized or invalid fields in Critical should cause an unrecoverable failure.
// This should also be _very_ paranoid about missing fields, duplicated fields, and the like, when decoding.
type Critical struct {
	Identity Identity `json:"identity"` // Identity claimed identity of the image
	Image    Image    `json:"image"`    // Image identifies the container that the signature applies to
	Type     string   `json:"type"`     // Type must be 'atomic container signature'
}

// Identity is the claimed identity of the image
type Identity struct {
	DockerReference string `json:"docker-reference"` // DockerReference is a reference used by users to refer to or download the image; it’s what the signer claims the image to be.
}

// Image identifies the container image that the signature applies to
type Image struct {
	DockerManifestDigest string `json:"docker-manifest-digest"` // DockerManifestDigest the manifest digest of the signed container image
}

// Cosign describes a container image signed using Cosign
type Cosign struct {
	// ClaimedIdentity is what the signer claims the image to be; usually a registry.com/…/repo:tag, but can also use a digest instead.
	// ALMOST ALL consumers MUST verify that ClaimedIdentity in the signature is correct given how user refers to the image;
	// e.g. if the user asks to access a signed image example.com/repo/mysql:3.14,
	// it is ALMOST ALWAYS necessary to validate that ClaimedIdentity = example.com/repo/mysql:3.14
	//
	// Considerations:
	// - The user might refer to an image using a digest (example.com/repo/mysql@sha256:…); in that case the registry/…/repo should still match
	// - If the image is multi-arch, ClaimedIdentity usually refers to the top-level multi-arch image index also on the per-arch images
	//   (possibly even if ClaimedIdentity contains a digest!)
	// - Older versions of cosign generate signatures where ClaimedIdentity only contains a registry/…/repo ; signature consumers should allow users
	//   to determine whether such images should be accepted (and, long-term, the default SHOULD be to reject them)
	ClaimedIdentity name.Reference
	// ImageDigest is the digest of the manifest being signed (typically "sha256:…"). It MUST exactly match the signed manifest;
	// for signatures of multi-arch image indices, it must match the image index; for signatures of the component per-arch images,
	// it must match the individual image.
	ImageDigest string
	Annotations map[string]interface{}
}

// SimpleContainerImage returns information about a container image in the github.com/containers/image/signature format
func (p Cosign) SimpleContainerImage() SimpleContainerImage {
	return SimpleContainerImage{
		Critical: Critical{
			Identity: Identity{
				DockerReference: p.ClaimedIdentity.Name(),
			},
			Image: Image{
				DockerManifestDigest: p.ImageDigest,
			},
			Type: CosignSignatureType,
		},
		Optional: p.Annotations,
	}
}

// MarshalJSON marshals the container signature into a []byte of JSON data
func (p Cosign) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.SimpleContainerImage())
}

var _ json.Marshaler = Cosign{}

// UnmarshalJSON unmarshals []byte of JSON data into a container signature object
func (p *Cosign) UnmarshalJSON(data []byte) error {
	// This is not used by sigstore/sigstore nor sigstore/cosign.
	//
	// If anyone choses to implement this:
	// Prefer sharing a single implementation with sigstore/cosign, wherever it ends up being located.
	// Per the simple signing payload specification, any unrecognized or invalid fields in Critical should cause an unrecoverable failure.
	// This should also be _very_ paranoid about missing fields, duplicated fields, and the like.
	return errors.New("Cosign.UnmarshalJSON is unimplemented; use sigstore/cosign.SimpleClainVerifier instead")
}

var _ json.Unmarshaler = (*Cosign)(nil)
