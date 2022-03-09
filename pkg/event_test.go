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
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func Test_GithubEventNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		env   map[string]string
		event GithubEvent
		err   error
	}{
		{
			name: "push event",
			env: map[string]string{
				"GITHUB_EVENT_NAME": "push",
				"GITHUB_EVENT_PATH": "testdata/push_payload_notag.json",
			},
			event: GithubEvent{
				Event:  "push",
				Branch: "refs/heads/main",
			},
		},
		{
			name: "push event with tag",
			env: map[string]string{
				"GITHUB_EVENT_NAME": "push",
				"GITHUB_EVENT_PATH": "testdata/push_payload_tag.json",
			},
			event: GithubEvent{
				Event:  "push",
				Branch: "refs/heads/main",
				Tag:    "refs/tags/simple-tag",
			},
		},
		{
			name: "workflow_dispatch event",
			env: map[string]string{
				"GITHUB_EVENT_NAME": "workflow_dispatch",
				"GITHUB_EVENT_PATH": "testdata/workflow_dispatch_payload.json",
			},
			event: GithubEvent{
				Event:  "workflow_dispatch",
				Branch: "refs/heads/main",
				User: User{
					Login: "laurentsimon",
					Type:  "User",
				},
			},
		},
		{
			name: "empty event",
			env: map[string]string{
				"GITHUB_EVENT_NAME": "",
				"GITHUB_EVENT_PATH": "testdata/push_payload_notag.json",
			},
			err: errorEnvNotSet,
		},
		{
			name: "unsupported event",
			env: map[string]string{
				"GITHUB_EVENT_NAME": "something",
				"GITHUB_EVENT_PATH": "testdata/push_payload_notag.json",
			},
			err: errorNotSupported,
		},
		{
			name: "non-existent event file",
			env: map[string]string{
				"GITHUB_EVENT_NAME": "push",
				"GITHUB_EVENT_PATH": "testdata/does-not-exist.json",
			},
			err: os.ErrNotExist,
		},
		// TODO: add support.
		{
			name: "unsupported schedule event",
			env: map[string]string{
				"GITHUB_EVENT_NAME": "schedule",
				"GITHUB_EVENT_PATH": "testdata/push_payload_notag.json",
			},
			err: errorNotSupported,
		},
	}
	for _, tt := range tests {
		tt := tt // Re-initializing variable so it is not changed while executing the closure below
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Set env variables.
			for k, v := range tt.env {
				os.Setenv(k, v)
			}

			c, err := GithubEventNew()

			if !errCmp(err, tt.err) {
				t.Errorf(cmp.Diff(err, tt.err))
			}

			if err != nil {
				return
			}

			if c == nil {
				t.Errorf("c is nil")
			}

			if !cmp.Equal(*c, tt.event) {
				t.Errorf(cmp.Diff(*c, tt.event))
			}
		})
	}
}
