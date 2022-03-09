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

type GitHubContext struct {
	Repository string `json:"repository"`
	ActionPath string `json:"action_path"`
	Workflow   string `json:"workflow"`
	RunId      string `json:"run_id"`
	EventName  string `json:"event_name"`
	SHA        string `json:"sha"`
	Token      string `json:"token,omitempty"`
	RunNumber  string `json:"run_number"`
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
    Version int
		Steps []Step `json:"steps"`
	}

	Parameters struct {
		Version int
		Event   string  `json:"event"`
		Branch  string  `json:"branch"`
		Tag     *string `json:"tag,omitempty"`  // May be nil: only populated for new tag push.
		User    *User   `json:"user,omitempty"` // May be nil: only populated for workflow_dispatch.
	}
)

// GenerateProvenance translates github context into a SLSA provenance
// attestation.
// Spec: https://slsa.dev/provenance/v0.1
func GenerateProvenance(name, digest, githubContext, command string) ([]byte, error) {
	gh := &GitHubContext{}
	if err := json.Unmarshal([]byte(githubContext), gh); err != nil {
		return nil, err
	}
	gh.Token = ""

	if _, err := hex.DecodeString(digest); err != nil || len(digest) != 64 {
		return nil, fmt.Errorf("sha256 digest is not valid: %s", digest)
	}

	com, err := unmarshallCommand(command)
	if err != nil {
		return nil, err
	}

	params, err := createParameters()
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
				// Add event inputs
				Environment: map[string]interface{}{
					"arch": "amd64", // TODO: Does GitHub run actually expose this?
					"env": map[string]string{
						"GITHUB_RUN_NUMBER": gh.RunNumber,
						"GITHUB_RUN_ID":     gh.RunId,
						"GITHUB_EVENT_NAME": gh.EventName,
					},
				},
				Parameters: params,
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

func createParameters() (Parameters, error) {
	ghPayload, err := GithubEventNew()
	if err != nil {
		if !errors.Is(err, errorNotSupported) {
			return Parameters{}, fmt.Errorf("GithubEventNew: %w", err)
		}
		// Allow empty parameters until we've added support for
		// schedule and other events.
		return Parameters{}, nil
	}

	params := Parameters{
		Version: parametersVersion,
		Event:   ghPayload.Event,
		Branch:  ghPayload.Branch,
	}

	// Add the tag.
	if ghPayload.Tag != "" {
		params.Tag = &ghPayload.Tag
	}

	// Add the user.
	if ghPayload.User.Login != "" || ghPayload.User.Type != "" {
		params.User = &ghPayload.User
	}

	return params, err
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
