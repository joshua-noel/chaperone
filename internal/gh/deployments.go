package gh

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// DeploymentRequest is the input of [Client.CreateDeployment].
type DeploymentRequest struct {
	Ref         string // branch or full SHA to record
	Environment string
	Description string
}

// Deployment is a GitHub deployment record.
type Deployment struct {
	ID          int64  `json:"id"`
	SHA         string `json:"sha"`
	Ref         string `json:"ref"`
	Environment string `json:"environment"`
	Description string `json:"description"`
}

// CreateDeployment records a deployment (POST /deployments). It is a record of
// a deploy Chaperone's host runner already did, not a gate, so the body sends
// auto_merge=false and required_contexts=[]: GitHub neither merges the base
// into the ref nor refuses on commit statuses. Needs `deployments: write`.
func (c *Client) CreateDeployment(ctx context.Context, tok *Token, repo Repo, in DeploymentRequest) (*Deployment, error) {
	if err := repo.validate(); err != nil {
		return nil, err
	}
	if err := validRef(in.Ref); err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.Environment) == "" {
		return nil, fmt.Errorf("%w: environment", ErrInvalidArgument)
	}
	secret, err := c.asToken(tok)
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"ref":               in.Ref,
		"environment":       in.Environment,
		"auto_merge":        false,
		"required_contexts": []string{},
	}
	if in.Description != "" {
		body["description"] = in.Description
	}
	var d Deployment
	if err := c.do(ctx, call{method: http.MethodPost, path: repo.path("/deployments"), body: body, secret: secret}, &d); err != nil {
		return nil, err
	}
	if d.ID == 0 {
		return nil, errors.New("gh: create deployment answered without an id")
	}
	return &d, nil
}

// Deployment states GitHub accepts.
const (
	DeployError      = "error"
	DeployFailure    = "failure"
	DeployInactive   = "inactive"
	DeployInProgress = "in_progress"
	DeployQueued     = "queued"
	DeployPending    = "pending"
	DeploySuccess    = "success"
)

// DeploymentStatusRequest is the input of [Client.CreateDeploymentStatus].
type DeploymentStatusRequest struct {
	State          string // one of the Deploy* constants
	Description    string
	EnvironmentURL string
	LogURL         string
}

// DeploymentStatus is a deployment status record.
type DeploymentStatus struct {
	ID    int64  `json:"id"`
	State string `json:"state"`
}

// CreateDeploymentStatus sets the state of a deployment (POST
// /deployments/{id}/statuses). Needs `deployments: write`.
func (c *Client) CreateDeploymentStatus(ctx context.Context, tok *Token, repo Repo, deploymentID int64, in DeploymentStatusRequest) (*DeploymentStatus, error) {
	if err := repo.validate(); err != nil {
		return nil, err
	}
	if deploymentID <= 0 {
		return nil, fmt.Errorf("%w: deployment id", ErrInvalidArgument)
	}
	switch in.State {
	case DeployError, DeployFailure, DeployInactive, DeployInProgress, DeployQueued, DeployPending, DeploySuccess:
	default:
		return nil, fmt.Errorf("%w: deployment state %q", ErrInvalidArgument, in.State)
	}
	secret, err := c.asToken(tok)
	if err != nil {
		return nil, err
	}
	body := map[string]string{"state": in.State}
	for k, v := range map[string]string{"description": in.Description, "environment_url": in.EnvironmentURL, "log_url": in.LogURL} {
		if v != "" {
			body[k] = v
		}
	}
	var s DeploymentStatus
	path := repo.path("/deployments/" + strconv.FormatInt(deploymentID, 10) + "/statuses")
	if err := c.do(ctx, call{method: http.MethodPost, path: path, body: body, secret: secret}, &s); err != nil {
		return nil, err
	}
	return &s, nil
}
