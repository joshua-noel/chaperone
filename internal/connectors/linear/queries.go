package linear

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
)

// The five documents chapd sends to Linear. They are constants: nothing from a
// caller is ever spliced into one. A caller's values reach Linear only as
// GraphQL variables, after the adapters validated them against the policy.
//
// The two mutations carry exactly the fields they need. commentCreate takes an
// id, an issue and a body; issueUpdate takes a state id and nothing else, so
// no title, description, label, assignee or archive change can be sent.
const (
	opList     = "IntakeList"
	opGuard    = "IntakeGuard"
	opTeam     = "IntakeTeam"
	opComment  = "IntakeComment"
	opSetState = "IntakeSetState"

	// The page and nesting sizes written into queryList.
	listPageSize = 25
	listComments = 8
	listLinks    = 8
)
const queryList = `query IntakeList($filter: IssueFilter!, $first: Int!, $after: String) {
  issues(filter: $filter, first: $first, after: $after, orderBy: updatedAt) {
    nodes {
      id
      identifier
      title
      description
      url
      createdAt
      updatedAt
      team { key name }
      state { name type }
      assignee { name }
      labels(first: 20) { nodes { name } }
      comments(first: 8) { nodes { body createdAt user { name } } }
      attachments(first: 8) { nodes { url title sourceType } }
    }
    pageInfo { hasNextPage endCursor }
  }
}`

// queryGuard reads what a write needs to decide: the issue's team (key and
// name), its state, whether it carries the label (the label connection is
// filtered to the one name), and the team's states by name and id.
const queryGuard = `query IntakeGuard($id: String!, $label: String!) {
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
    labels(first: 5, filter: { name: { eq: $label } }) { nodes { name } }
  }
}`

const queryTeam = `query IntakeTeam($key: String!) {
  teams(filter: { key: { eq: $key } }, first: 1) {
    nodes {
      key
      name
      states(first: 100) { nodes { id name type } }
    }
  }
}`

const mutationComment = `mutation IntakeComment($input: CommentCreateInput!) {
  commentCreate(input: $input) {
    success
    comment { id url }
  }
}`

const mutationSetState = `mutation IntakeSetState($id: String!, $input: IssueUpdateInput!) {
  issueUpdate(id: $id, input: $input) {
    success
    issue { identifier state { name } }
  }
}`

// State is a workflow state of a team.
type State struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// Comment is one comment of an item.
type Comment struct {
	Author    string
	CreatedAt string
	Body      string
}

// Link is one attachment (a link) of an item.
type Link struct {
	URL    string
	Title  string
	Source string
}

// Item is one issue of the board, as the list shows it. The text fields are
// untrusted.
type Item struct {
	Identifier  string
	Title       string
	Description string
	URL         string
	CreatedAt   string
	UpdatedAt   string
	State       State
	Assignee    string
	Labels      []string
	Comments    []Comment
	Links       []Link
	// MoreComments and MoreLinks are set when the issue has more than the list returns.
	MoreComments bool
	MoreLinks    bool
}

type nodes[T any] struct {
	Nodes []T `json:"nodes"`
}

type rawIssue struct {
	ID          string `json:"id"`
	Identifier  string `json:"identifier"`
	Title       string `json:"title"`
	Description string `json:"description"`
	URL         string `json:"url"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
	Team        struct {
		Key  string `json:"key"`
		Name string `json:"name"`
	} `json:"team"`
	State    State `json:"state"`
	Assignee *struct {
		Name string `json:"name"`
	} `json:"assignee"`
	Labels   labelConn `json:"labels"`
	Comments nodes[struct {
		Body      string `json:"body"`
		CreatedAt string `json:"createdAt"`
		User      *struct {
			Name string `json:"name"`
		} `json:"user"`
	}] `json:"comments"`
	Attachments nodes[struct {
		URL        string `json:"url"`
		Title      string `json:"title"`
		SourceType string `json:"sourceType"`
	}] `json:"attachments"`
}

// ListItems reads the open items of one team that carry one label, newest
// change first, at most max of them. includeClosed also returns completed and
// canceled items. truncated is true when there are more than max.
//
// The team and label come from the policy, never from a caller. Items whose
// team is not the team asked for are dropped: a filter Linear applied wrongly
// must not put another team's text in a result.
func (c *Client) ListItems(ctx context.Context, team, label string, includeClosed bool, max int) (items []Item, truncated bool, err error) {
	filter := map[string]any{
		"team":   map[string]any{"key": map[string]any{"eq": team}},
		"labels": map[string]any{"some": map[string]any{"name": map[string]any{"eq": label}}},
	}
	if !includeClosed {
		filter["state"] = map[string]any{"type": map[string]any{"nin": []string{"completed", "canceled"}}}
	}
	var after any
	for pages := 0; ; pages++ {
		var out struct {
			Issues struct {
				Nodes    []rawIssue `json:"nodes"`
				PageInfo struct {
					HasNextPage bool   `json:"hasNextPage"`
					EndCursor   string `json:"endCursor"`
				} `json:"pageInfo"`
			} `json:"issues"`
		}
		vars := map[string]any{"filter": filter, "first": listPageSize, "after": after}
		if err := c.do(ctx, opList, queryList, vars, &out); err != nil {
			return nil, false, err
		}
		for _, n := range out.Issues.Nodes {
			if n.Team.Key != team {
				continue
			}
			if len(items) == max {
				return items, true, nil
			}
			items = append(items, n.item())
		}
		if !out.Issues.PageInfo.HasNextPage || out.Issues.PageInfo.EndCursor == "" || pages >= 10 {
			return items, out.Issues.PageInfo.HasNextPage, nil
		}
		after = out.Issues.PageInfo.EndCursor
	}
}

func (n rawIssue) item() Item {
	it := Item{
		Identifier: n.Identifier, Title: n.Title, Description: n.Description, URL: n.URL,
		CreatedAt: n.CreatedAt, UpdatedAt: n.UpdatedAt, State: State{Name: n.State.Name, Type: n.State.Type},
	}
	if n.Assignee != nil {
		it.Assignee = n.Assignee.Name
	}
	for _, l := range n.Labels.Nodes {
		it.Labels = append(it.Labels, l.Name)
	}
	for _, cm := range n.Comments.Nodes {
		c := Comment{CreatedAt: cm.CreatedAt, Body: cm.Body}
		if cm.User != nil {
			c.Author = cm.User.Name
		}
		it.Comments = append(it.Comments, c)
	}
	for _, a := range n.Attachments.Nodes {
		it.Links = append(it.Links, Link{URL: a.URL, Title: a.Title, Source: a.SourceType})
	}
	it.MoreComments = len(n.Comments.Nodes) >= listComments
	it.MoreLinks = len(n.Attachments.Nodes) >= listLinks
	return it
}

// Guard is what a write decides on, read from Linear just before it.
type Guard struct {
	ID         string // Linear's id of the issue; the mutations use it, not the identifier
	Identifier string
	Title      string
	URL        string
	TeamKey    string
	TeamName   string
	State      State
	HasLabel   bool
	States     []State // the issue's team's states
}

// Guard reads the issue named by identifier and whether it carries label.
// Linear resolves an identifier that an issue had before it moved to another
// team, so the caller must compare TeamKey and not trust the identifier.
func (c *Client) Guard(ctx context.Context, identifier, label string) (*Guard, error) {
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
			State  State                        `json:"state"`
			Labels nodes[struct{ Name string }] `json:"labels"`
		} `json:"issue"`
	}
	err := c.do(ctx, opGuard, queryGuard, map[string]any{"id": identifier, "label": label}, &out)
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
	g := &Guard{
		ID: i.ID, Identifier: i.Identifier, Title: i.Title, URL: i.URL,
		TeamKey: i.Team.Key, TeamName: i.Team.Name, State: i.State, States: i.Team.States.Nodes,
	}
	for _, l := range i.Labels.Nodes {
		if l.Name == label {
			g.HasLabel = true
		}
	}
	return g, nil
}

func notFoundText(s string) bool {
	s = strings.ToLower(s)
	return strings.Contains(s, "not found") || strings.Contains(s, "could not find")
}

// Team is a team and its workflow states.
type Team struct {
	Key    string
	Name   string
	States []State
}

// TeamStates reads the team with the key. ErrNotFound when Linear has none
// (or the app cannot see it).
func (c *Client) TeamStates(ctx context.Context, key string) (*Team, error) {
	var out struct {
		Teams nodes[struct {
			Key    string       `json:"key"`
			Name   string       `json:"name"`
			States nodes[State] `json:"states"`
		}] `json:"teams"`
	}
	if err := c.do(ctx, opTeam, queryTeam, map[string]any{"key": key}, &out); err != nil {
		return nil, err
	}
	for _, t := range out.Teams.Nodes {
		if t.Key == key {
			return &Team{Key: t.Key, Name: t.Name, States: t.States.Nodes}, nil
		}
	}
	return nil, ErrNotFound
}

// CommentID is the comment id chapd chooses for a request: a version 4 UUID
// derived from the request's execution id, so the comment of an unconfirmed
// op can be looked up and a repeat of the same execution cannot make a second.
func CommentID(executionID string) string {
	h := sha256.Sum256([]byte("chap-linear-comment-v1\x00" + executionID))
	b := h[:16]
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// CreatedComment is what Linear answers to a comment.
type CreatedComment struct {
	ID  string
	URL string
}

// AddComment posts body as a comment on the issue with Linear id issueID. The
// input has these four fields and no other.
func (c *Client) AddComment(ctx context.Context, commentID, issueID, body string) (*CreatedComment, error) {
	var out struct {
		CommentCreate struct {
			Success bool `json:"success"`
			Comment *struct {
				ID  string `json:"id"`
				URL string `json:"url"`
			} `json:"comment"`
		} `json:"commentCreate"`
	}
	in := map[string]any{"id": commentID, "issueId": issueID, "body": body}
	if err := c.do(ctx, opComment, mutationComment, map[string]any{"input": in}, &out); err != nil {
		return nil, err
	}
	cc := out.CommentCreate
	if !cc.Success || cc.Comment == nil {
		return nil, &GraphQLError{Message: "Linear did not confirm the comment"}
	}
	return &CreatedComment{ID: cc.Comment.ID, URL: cc.Comment.URL}, nil
}

// SetState moves the issue with Linear id issueID to the state with id
// stateID. The input has that one field. It returns the state name Linear
// reports.
func (c *Client) SetState(ctx context.Context, issueID, stateID string) (string, error) {
	var out struct {
		IssueUpdate struct {
			Success bool `json:"success"`
			Issue   *struct {
				State struct {
					Name string `json:"name"`
				} `json:"state"`
			} `json:"issue"`
		} `json:"issueUpdate"`
	}
	in := map[string]any{"stateId": stateID}
	if err := c.do(ctx, opSetState, mutationSetState, map[string]any{"id": issueID, "input": in}, &out); err != nil {
		return "", err
	}
	u := out.IssueUpdate
	if !u.Success || u.Issue == nil {
		return "", &GraphQLError{Message: "Linear did not confirm the move"}
	}
	return u.Issue.State.Name, nil
}
