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
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type pushPayload struct {
	Ref     string `yaml:"ref"`
	BaseRef string `yaml:"base_ref"`
}

type workflowDispatchPayload struct {
	Ref    string `yaml:"ref"`
	Sender struct {
		Login string `yaml:"login"`
		Type  string `yaml:"type"`
	} `yaml:"sender"`
}

type User struct {
	Login string
	Type  string
}

type GithubEvent struct {
	Event  string
	Branch string
	Tag    string
	User   User
}

var (
	errorEnvNotSet    = errors.New("env variable not set")
	errorNotSupported = errors.New("not supported")
	errorEmptyRef     = errors.New("empty ref")
)

func GithubEventNew() (*GithubEvent, error) {
	var c *GithubEvent
	var err error

	// See env variables available during a workflow run in
	// https://docs.github.com/en/actions/learn-github-actions/environment-variables#default-environment-variables.
	event := os.Getenv("GITHUB_EVENT_NAME")
	if event == "" {
		return nil, fmt.Errorf("GITHUB_EVENT_NAME: %w", errorEnvNotSet)
	}

	switch event {
	case "push":
		c, err = createEventFromPush()
		if err != nil {
			return nil, fmt.Errorf("push event: %w", err)
		}
	case "schedule":
		c, err = createEventFromSchedule()
		if err != nil {
			return nil, fmt.Errorf("schedule event: %w", err)
		}
	case "workflow_dispatch":
		c, err = createEventFromDispatch()
		if err != nil {
			return nil, fmt.Errorf("workflow_dispatch event: %w", err)
		}
	default:
		c, err = createDefaultEvent()
		if err != nil {
			return nil, fmt.Errorf("%s event: %w", event, err)
		}
	}
	return c, nil
}

func readEventContent() ([]byte, error) {
	path := os.Getenv("GITHUB_EVENT_PATH")
	if path == "" {
		return nil, fmt.Errorf("GITHUB_EVENT_PATH: %w", errorEnvNotSet)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("os.ReadFile: %w", err)
	}
	return content, nil
}

func createEventFromDispatch() (*GithubEvent, error) {
	var payload workflowDispatchPayload
	content, err := readEventContent()
	if err != nil {
		return nil, err
	}

	if err := yaml.Unmarshal([]byte(content), &payload); err != nil {
		return nil, fmt.Errorf("yaml.Unmarshal: %w", err)
	}

	if payload.Ref == "" {
		return nil, fmt.Errorf("%w", errorEmptyRef)
	}

	return &GithubEvent{
		Event:  "workflow_dispatch",
		Branch: payload.Ref,
		User: User{
			Login: payload.Sender.Login,
			Type:  payload.Sender.Type,
		},
	}, nil
}

func createEventFromPush() (*GithubEvent, error) {
	var payload pushPayload
	content, err := readEventContent()
	if err != nil {
		return nil, err
	}

	if err := yaml.Unmarshal([]byte(content), &payload); err != nil {
		return nil, fmt.Errorf("yaml.Unmarshal: %w", err)
	}

	if payload.Ref == "" {
		return nil, fmt.Errorf("%w", errorEmptyRef)
	}

	// Base is empty if it's a push without a new tag.
	if payload.BaseRef == "" {
		return &GithubEvent{
			Event:  "push",
			Branch: payload.Ref,
		}, nil
	}

	// Non-empty baseRef means a new tag.
	return &GithubEvent{
		Event:  "push",
		Branch: payload.BaseRef,
		Tag:    payload.Ref,
	}, nil
}

func createEventFromSchedule() (*GithubEvent, error) {
	// TODO
	return nil, fmt.Errorf("%w", errorNotSupported)
}

func createDefaultEvent() (*GithubEvent, error) {
	// TODO
	return nil, fmt.Errorf("%w", errorNotSupported)
}
