package repo

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/chia-network/repo-content-updater/internal/config"
	"github.com/go-git/go-git/v5"
	"github.com/google/go-github/v59/github"
)

func TestArchivedRepositoryUpdates(t *testing.T) {
	commands := []struct {
		name string
		run  func(*Content, *config.Config) error
	}{
		{"managed-files", func(c *Content, cfg *config.Config) error {
			return c.checkSelectedFiles("test-repo", config.ManagedFileSelection{}, cfg, CustomProperties{})
		}},
		{"debug-repo", func(c *Content, cfg *config.Config) error {
			return c.CheckFiles("test-repo", nil, cfg, CustomProperties{})
		}},
		{"license", func(c *Content, cfg *config.Config) error {
			return c.UpdateLicense("test-repo", cfg, CustomProperties{})
		}},
	}
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"archived", http.StatusOK, `{"archived":true}`},
		{"lookup-failed", http.StatusForbidden, `{"message":"Forbidden"}`},
		{"active", http.StatusOK, `{"archived":false}`},
	}
	for _, command := range commands {
		for _, tc := range cases {
			t.Run(command.name+"/"+tc.name, func(t *testing.T) {
				t.Chdir(t.TempDir())
				var calls atomic.Int64
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if r.Method != http.MethodGet || r.URL.Path != "/repos/test-org/test-repo" {
						t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tc.status)
					if _, err := fmt.Fprint(w, tc.body); err != nil {
						t.Errorf("write response: %v", err)
					}
				}))
				defer server.Close()
				client := github.NewClient(server.Client())
				baseURL, err := url.Parse(server.URL + "/")
				if err != nil {
					t.Fatal(err)
				}
				client.BaseURL = baseURL
				content := &Content{githubClient: client, githubOrg: "test-org"}
				// An existing Git repository makes an active repo's clone fail locally.
				var cfg *config.Config
				if tc.name == "active" {
					cfg = &config.Config{}
					if _, err := git.PlainInit(repoDir("test-repo"), false); err != nil {
						t.Fatal(err)
					}
				}
				// Nil config proves archived repos and lookup failures stop in the per-repo routine.
				err = command.run(content, cfg)
				switch tc.name {
				case "archived":
					if err != nil {
						t.Fatalf("archived repository should be skipped successfully: %v", err)
					}
				case "lookup-failed":
					if err == nil || !strings.Contains(err.Error(), "test-repo") {
						t.Fatalf("lookup failure must identify the repository: %v", err)
					}
				case "active":
					if !errors.Is(err, git.ErrRepositoryAlreadyExists) {
						t.Fatalf("active repository must proceed to cloning: %v", err)
					}
				}
				if got := calls.Load(); got != 1 {
					t.Errorf("got %d API calls, want only the repository lookup", got)
				}
				if _, err := os.Stat(repoDir("test-repo")); !os.IsNotExist(err) {
					t.Errorf("repository must not remain on disk; stat error: %v", err)
				}
			})
		}
	}
}
