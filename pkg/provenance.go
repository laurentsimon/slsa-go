// Copyright The GOSST team.
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

package pkg

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsa "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/providers"
	_ "github.com/sigstore/cosign/pkg/providers/all"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
)

const (
	defaultFulcioAddr   = "https://v1.fulcio.sigstore.dev"
	defaultOIDCIssuer   = "https://oauth2.sigstore.dev/auth"
	defaultOIDCClientID = "sigstore"
	defaultRekorAddr    = "https://rekor.sigstore.dev"
)

type gitHubContext struct {
	Repository string `json:"repository"`
	ActionPath string `json:"action_path"`
	Workflow   string `json:"workflow"`
	EventName  string `json:"event_name"`
	SHA        string `json:"sha"`
	RefType    string `json:"ref_type"`
	Ref        string `json:"ref"`
	BaseRef    string `json:"base_ref"`
	HeadRef    string `json:"head_ref"`
	Actor      string `json:"actor"`
	RunNumber  string `json:"run_number"`
	RunID      string `json:"run_id"`
	RunAttempt string `json:"run_attempt"`
}

var (
	parametersVersion  int = 1
	buildConfigVersion int = 1
)

type (
	Step struct {
		Command []string `json:"command"`
		Env     []string `json:"env"`
	}
	BuildConfig struct {
		Version int    `json:"version"`
		Steps   []Step `json:"steps"`
	}

	Parameters struct {
		Version   int    `json:"version"`
		EventName string `json:"event_name"`
		RefType   string `json:"ref_type"`
		Ref       string `json:"ref"`
		BaseRef   string `json:"base_ref"`
		HeadRef   string `json:"head_ref"`
		Actor     string `json:"actor"`
	}
)

// GenerateProvenance translates github context into a SLSA provenance
// attestation.
// Spec: https://slsa.dev/provenance/v0.1
func GenerateProvenance(name, digest, ghContext, command string) ([]byte, error) {
	gh := &gitHubContext{}
	if err := json.Unmarshal([]byte(ghContext), gh); err != nil {
		return nil, err
	}

	if _, err := hex.DecodeString(digest); err != nil || len(digest) != 64 {
		return nil, fmt.Errorf("sha256 digest is not valid: %s", digest)
	}

	com, err := unmarshallCommand(command)
	if err != nil {
		return nil, err
	}

	att := intoto.ProvenanceStatement{
		StatementHeader: intoto.StatementHeader{
			Type:          intoto.StatementInTotoV01,
			PredicateType: slsa.PredicateSLSAProvenance,
			Subject: []intoto.Subject{
				{
					Name: name,
					Digest: slsa.DigestSet{
						"sha256": digest,
					},
				},
			},
		},
		Predicate: slsa.ProvenancePredicate{
			BuildType: "https://github.com/Attestations/GitHubHostedReusableWorkflow@v1",
			Builder: slsa.ProvenanceBuilder{
				// TODO(https://github.com/in-toto/in-toto-golang/issues/159): add
				// version and hash.
				ID: "gossts/slsa-go/blob/main/.github/workflows/builder.yml",
			},
			Invocation: slsa.ProvenanceInvocation{
				ConfigSource: slsa.ConfigSource{
					EntryPoint: gh.Workflow,
					URI:        fmt.Sprintf("git+%s.git", gh.Repository),
					Digest: slsa.DigestSet{
						"SHA1": gh.SHA,
					},
				},
				// Non-user-controllable things needed to reproduce the build.
				Environment: map[string]interface{}{
					"arch":               "amd64", // TODO: Does GitHub run actually expose this?
					"os":                 "ubuntu",
					"github_event_name":  gh.EventName,
					"github_run_number":  gh.RunNumber,
					"github_run_id":      gh.RunID,
					"github_run_attempt": gh.RunAttempt,
				},
				// Parameters coming from the trigger event.
				Parameters: Parameters{
					Version:   parametersVersion,
					EventName: gh.EventName,
					Ref:       gh.Ref,
					BaseRef:   gh.BaseRef,
					HeadRef:   gh.HeadRef,
					Actor:     gh.Actor,
				},
			},
			BuildConfig: BuildConfig{
				Version: buildConfigVersion,
				Steps: []Step{
					// Single step.
					{
						Command: com,
						// TODO: env variables.
					},
				},
			},
			Materials: []slsa.ProvenanceMaterial{
				{
					URI: fmt.Sprintf("git+%s.git", gh.Repository),
					Digest: slsa.DigestSet{
						"SHA1": gh.SHA,
					},
				},
			},
		},
	}

	attBytes, err := json.Marshal(att)
	if err != nil {
		return nil, err
	}

	// Get Fulcio signer
	ctx := context.Background()
	if !providers.Enabled(ctx) {
		return nil, fmt.Errorf("no auth provider for fulcio is enabled")
	}

	fClient, err := fulcio.NewClient(defaultFulcioAddr)
	if err != nil {
		return nil, err
	}
	tok, err := providers.Provide(ctx, defaultOIDCClientID)
	if err != nil {
		return nil, err
	}
	k, err := fulcio.NewSigner(ctx, tok, defaultOIDCIssuer, defaultOIDCClientID, "", fClient)
	if err != nil {
		return nil, err
	}
	wrappedSigner := dsse.WrapSigner(k, intoto.PayloadType)

	signedAtt, err := wrappedSigner.SignMessage(bytes.NewReader(attBytes))
	if err != nil {
		return nil, err
	}

	// Upload to tlog
	rekorClient, err := rekor.NewClient(defaultRekorAddr)
	if err != nil {
		return nil, err
	}
	// TODO: Is it a bug that we need []byte(string(k.Cert)) or else we hit invalid PEM?
	if _, err := cosign.TLogUploadInTotoAttestation(ctx, rekorClient, signedAtt, []byte(string(k.Cert))); err != nil {
		return nil, err
	}

	return signedAtt, nil
}

func unmarshallCommand(command string) ([]string, error) {
	var res []string
	cs, err := base64.StdEncoding.DecodeString(command)
	if err != nil {
		return res, fmt.Errorf("base64.StdEncoding.DecodeString: %w", err)
	}

	if err := json.Unmarshal(cs, &res); err != nil {
		return []string{}, fmt.Errorf("json.Unmarshal: %w", err)
	}
	return res, nil
}

func verifyProvenanceName(name string) error {
	const alpha = "abcdefghijklmnopqrstuvwxyz1234567890-_"

	if name == "" {
		return errors.New("empty provenance name")
	}

	for _, char := range name {
		if !strings.Contains(alpha, strings.ToLower(string(char))) {
			return fmt.Errorf("invalid filename: found character '%c' in %s", char, name)
		}
	}

	return nil
}
