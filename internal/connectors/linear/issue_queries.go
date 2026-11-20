package linear

import (
	"context"
	"errors"
	"strings"
)

// The documents of the generic issue ops (`issue.get|list|comment|label|move|
// link`). Like the five intake documents they are constants: a caller's values
// reach Linear only as GraphQL variables, after the adapter checked them
// against the policy. `issue.comment` and `issue.move` send the intake
// mutations (IntakeComment, IntakeSetState) unchanged.
//
// What each can do:
//
//   - IssueGet, IssueList, IssueGuard and IssueLabelLookup are queries.
//   - IssueAddLabel and IssueRemoveLabel take an issue id and one label id.
//     Linear adds or removes that one label atomically, so a label a person set
//     in the meantime is never overwritten (no `labelIds` list is ever sent).
//   - IssueLink takes an issue id, a URL and a title.
//
// There is no document that creates, edits, assigns, archives or deletes an
// issue.
const (
	opIssueGet     = "IssueGet"
	opIssueList    = "IssueList"
	opIssueGuard   = "IssueGuard"
	opIssueLabel   = "IssueLabelLookup"
	opIssueAdd     = "IssueAddLabel"
	opIssueRemove  = "IssueRemoveLabel"
	opIssueLink    = "IssueLink"
	issueLabelPage = 50
)

// issueNode is the issue as IssueGet and IssueList read it. The labels are
// asked for 50 at a time with their page info: an issue whose labels do not
// fit one page cannot be shown free of the intake label, so it is refused
// (the adapters fail closed on LabelsMore).
const issueNode = `id
    identifier
    title
    description
    url
    createdAt
    updatedAt
    team { key name }
    state { name type }
    assignee { name }
    labels(first: 50) { nodes { name } pageInfo { hasNextPage } }
    comments(first: 8) { nodes { body createdAt user { name } } }
    attachments(first: 8) { nodes { url title sourceType } }`

const queryIssueGet = `query IssueGet($id: String!) {
  issue(id: $id) {
    ` + issueNode + `
  }
}`

const queryIssueList = `query IssueList($filter: IssueFilter!, $first: Int!, $after: String) {
  issues(filter: $filter, first: $first, after: $after, orderBy: updatedAt) {
    nodes {
      ` + issueNode + `
    }
    pageInfo { hasNextPage endCursor }
  }
}`

// queryIssueGuard reads what an issue write decides on: the issue's team, its
// state, every label it carries (with ids) and the team's states.
const queryIssueGuard = `query IssueGuard($id: String!) {
  issue(id: $id) {
    id
    identifier
    title
    url
    team {
      key
      name
      states(first: 100) { nodes { id name type } }
    }
    state { id name type }
    labels(first: 50) { nodes { id name } pageInfo { hasNextPage } }
  }
}`

const queryIssueLabel = `query IssueLabelLookup($name: String!) {
  issueLabels(filter: { name: { eq: $name } }, first: 10) {
    nodes { id name team { key } }
  }
}`

const mutationIssueAddLabel = `mutation IssueAddLabel($id: String!, $labelId: String!) {
  issueAddLabel(id: $id, labelId: $labelId) {
    success
    issue { identifier }
  }
}`

const mutationIssueRemoveLabel = `mutation IssueRemoveLabel($id: String!, $labelId: String!) {
  issueRemoveLabel(id: $id, labelId: $labelId) {
    success
    issue { identifier }
  }
}`

const mutationIssueLink = `mutation IssueLink($input: AttachmentCreateInput!) {
  attachmentCreate(input: $input) {
    success
    attachment { id url }
  }
}`

type labelConn struct {
	Nodes []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"nodes"`
	PageInfo struct {
		HasNextPage bool `json:"hasNextPage"`
	} `json:"pageInfo"`
}

// IssueView is an issue as `issue.get` and `issue.list` show it, with what the
// adapters need to apply the policy before any of its text is returned.
type IssueView struct {
	Item
	TeamKey  string
	TeamName string
	// LabelsMore is set when the issue has more labels than one page holds.
	LabelsMore bool
}

// view turns a raw issue into an [IssueView].
func (n rawIssue) view() IssueView {
	return IssueView{Item: n.item(), TeamKey: n.Team.Key, TeamName: n.Team.Name, LabelsMore: n.Labels.PageInfo.HasNextPage}
}

// GetIssue reads the issue named by identifier. ErrNotFound when Linear has
// none that the app can see. The caller must compare TeamKey and the labels
// with the policy: Linear resolves an identifier an issue had before it moved.
func (c *Client) GetIssue(ctx context.Context, identifier string) (*IssueView, error) {
	var out struct {
		Issue *rawIssue `json:"issue"`
	}
	err := c.do(ctx, opIssueGet, queryIssueGet, map[string]any{"id": identifier}, &out)
	var gq *GraphQLError
	if errors.As(err, &gq) && notFoundText(gq.Message) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if out.Issue == nil || out.Issue.ID == "" {
		return nil, ErrNotFound
	}
	v := out.Issue.view()
	return &v, nil
}

// IssuePage is one page of `issue.list`.
type IssuePage struct {
	Issues []IssueView
	// Next is the opaque cursor of the next page; empty on the last page.
	Next string
}

// ListIssues reads one page (at most listPageSize) of the issues of one team,
// newest change first, optionally of one workflow state type and carrying one
// label. The team comes from the policy; state and label are validated by the
// adapter. cursor is Linear's own, passed back as a variable.
func (c *Client) ListIssues(ctx context.Context, team, stateType, label, cursor string) (*IssuePage, error) {
	filter := map[string]any{"team": map[string]any{"key": map[string]any{"eq": team}}}
	if stateType != "" {
		filter["state"] = map[string]any{"type": map[string]any{"eq": stateType}}
	}
	if label != "" {
		filter["labels"] = map[string]any{"some": map[string]any{"name": map[string]any{"eq": label}}}
	}
	var after any
	if cursor != "" {
		after = cursor
	}
	var out struct {
		Issues struct {
			Nodes    []rawIssue `json:"nodes"`
			PageInfo struct {
				HasNextPage bool   `json:"hasNextPage"`
				EndCursor   string `json:"endCursor"`
			} `json:"pageInfo"`
		} `json:"issues"`
	}
	if err := c.do(ctx, opIssueList, queryIssueList, map[string]any{"filter": filter, "first": listPageSize, "after": after}, &out); err != nil {
		return nil, err
	}
	page := &IssuePage{}
	for _, n := range out.Issues.Nodes {
		page.Issues = append(page.Issues, n.view())
	}
	if out.Issues.PageInfo.HasNextPage {
		page.Next = out.Issues.PageInfo.EndCursor
	}
	return page, nil
}

// Label is a label of an issue, with Linear's id.
type Label struct{ ID, Name string }

// IssueGuardRead is what an issue write decides on, read from Linear just
// before it.
type IssueGuardRead struct {
	ID         string
	Identifier string
	Title      string
	URL        string
	TeamKey    string
	TeamName   string
	State      State
	States     []State // the issue's team's states
	Labels     []Label
	LabelsMore bool
}

// HasLabel reports whether the issue carries the label (compared without
// regard to case).
func (g *IssueGuardRead) HasLabel(name string) (Label, bool) {
	for _, l := range g.Labels {
		if strings.EqualFold(l.Name, name) {
			return l, true
		}
	}
	return Label{}, false
}

// LabelNames lists the names of the issue's labels.
func (g *IssueGuardRead) LabelNames() []string {
	out := make([]string, 0, len(g.Labels))
	for _, l := range g.Labels {
		out = append(out, l.Name)
	}
	return out
}

// ReadIssueGuard reads the issue named by identifier. ErrNotFound when Linear
// has none that the app can see.
func (c *Client) ReadIssueGuard(ctx context.Context, identifier string) (*IssueGuardRead, error) {
	var out struct {
		Issue *struct {
			ID         string `json:"id"`
			Identifier string `json:"identifier"`
			Title      string `json:"title"`
			URL        string `json:"url"`
			Team       struct {
				Key    string       `json:"key"`
				Name   string       `json:"name"`
				States nodes[State] `json:"states"`
			} `json:"team"`
			State  State     `json:"state"`
			Labels labelConn `json:"labels"`
		} `json:"issue"`
	}
	err := c.do(ctx, opIssueGuard, queryIssueGuard, map[string]any{"id": identifier}, &out)
	var gq *GraphQLError
	if errors.As(err, &gq) && notFoundText(gq.Message) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	i := out.Issue
	if i == nil || i.ID == "" {
		return nil, ErrNotFound
	}
	g := &IssueGuardRead{
		ID: i.ID, Identifier: i.Identifier, Title: i.Title, URL: i.URL,
		TeamKey: i.Team.Key, TeamName: i.Team.Name, State: i.State, States: i.Team.States.Nodes,
		LabelsMore: i.Labels.PageInfo.HasNextPage,
	}
	for _, l := range i.Labels.Nodes {
		g.Labels = append(g.Labels, Label{ID: l.ID, Name: l.Name})
	}
	return g, nil
}

// FindLabel resolves a label name to Linear's id for an issue of the team: the
// workspace label or the team's own label of exactly that name. ErrNotFound when
// there is none.
func (c *Client) FindLabel(ctx context.Context, name, teamKey string) (Label, error) {
	var out struct {
		IssueLabels struct {
			Nodes []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
				Team *struct {
					Key string `json:"key"`
				} `json:"team"`
			} `json:"nodes"`
		} `json:"issueLabels"`
	}
	if err := c.do(ctx, opIssueLabel, queryIssueLabel, map[string]any{"name": name}, &out); err != nil {
		return Label{}, err
	}
	for _, l := range out.IssueLabels.Nodes {
		if l.Name == name && (l.Team == nil || l.Team.Key == teamKey) {
			return Label{ID: l.ID, Name: l.Name}, nil
		}
	}
	return Label{}, ErrNotFound
}

// ChangeLabel adds (add true) or removes the one label with Linear id labelID
// to or from the issue with Linear id issueID.
func (c *Client) ChangeLabel(ctx context.Context, issueID, labelID string, add bool) error {
	name, doc, field := opIssueRemove, mutationIssueRemoveLabel, "issueRemoveLabel"
	if add {
		name, doc, field = opIssueAdd, mutationIssueAddLabel, "issueAddLabel"
	}
	var out map[string]struct {
		Success bool `json:"success"`
	}
	if err := c.do(ctx, name, doc, map[string]any{"id": issueID, "labelId": labelID}, &out); err != nil {
		return err
	}
	if !out[field].Success {
		return &GraphQLError{Message: "Linear did not confirm the label change"}
	}
	return nil
}

// AddLink attaches the URL to the issue with Linear id issueID. The input has
// these three fields and no other; Linear keeps one attachment per issue and
// URL, so a repeat does not duplicate.
func (c *Client) AddLink(ctx context.Context, issueID, url, title string) error {
	in := map[string]any{"issueId": issueID, "url": url}
	if title != "" {
		in["title"] = title
	}
	var out struct {
		AttachmentCreate struct {
			Success bool `json:"success"`
		} `json:"attachmentCreate"`
	}
	if err := c.do(ctx, opIssueLink, mutationIssueLink, map[string]any{"input": in}, &out); err != nil {
		return err
	}
	if !out.AttachmentCreate.Success {
		return &GraphQLError{Message: "Linear did not confirm the link"}
	}
	return nil
}
