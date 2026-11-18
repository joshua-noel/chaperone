package ops

import (
	"context"
	"fmt"
	"sync"

	"github.com/joshua-noel/chaperone/internal/gh"
)

// TokenMinter mints one installation token narrowed to one repository and a
// permission set (ADR-002 item 1). The caller revokes it.
type TokenMinter interface {
	Mint(ctx context.Context, repo gh.Repo, perms map[string]string) (*gh.Token, error)
}

// InstallationMinter is the production [TokenMinter]: it finds the App
// installation of the repository (cached) and mints a token narrowed to that
// one repository.
type InstallationMinter struct {
	Client *gh.Client

	mu    sync.Mutex
	known map[string]int64
}

// Mint implements [TokenMinter].
func (m *InstallationMinter) Mint(ctx context.Context, repo gh.Repo, perms map[string]string) (*gh.Token, error) {
	id, err := m.installation(ctx, repo)
	if err != nil {
		return nil, err
	}
	tok, err := m.Client.MintToken(ctx, id, gh.TokenRequest{Repositories: []string{repo.Name}, Permissions: perms})
	if err != nil {
		return nil, fmt.Errorf("mint token for %s: %w", repo, err)
	}
	return tok, nil
}

func (m *InstallationMinter) installation(ctx context.Context, repo gh.Repo) (int64, error) {
	key := repo.String()
	m.mu.Lock()
	id, ok := m.known[key]
	m.mu.Unlock()
	if ok {
		return id, nil
	}
	in, err := m.Client.FindInstallation(ctx, repo)
	if err != nil {
		return 0, fmt.Errorf("find installation of %s: %w", repo, err)
	}
	m.mu.Lock()
	if m.known == nil {
		m.known = make(map[string]int64)
	}
	m.known[key] = in.ID
	m.mu.Unlock()
	return in.ID, nil
}
