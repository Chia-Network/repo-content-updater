package repo

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/chia-network/repo-content-updater/internal/config"
	"github.com/google/go-github/v59/github"
)

func TestArchivedRepositoryUpdates(t *testing.T) {
	for _, command := range []string{"managed-files", "license"} {
		for _, status := range []int{http.StatusOK, http.StatusForbidden} {
			t.Run(fmt.Sprintf("%s/%d", command, status), func(t *testing.T) {
				calls := 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					if r.Method != http.MethodGet || r.URL.Path != "/repos/test-org/archived-repo" {
						t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(status)
					if status == http.StatusOK {
						fmt.Fprint(w, `{"archived":true}`)
					} else {
						fmt.Fprint(w, `{"message":"Forbidden"}`)
					}
				}))
				defer server.Close()
				client := github.NewClient(server.Client())
				client.BaseURL, _ = url.Parse(server.URL + "/")
				content := &Content{githubClient: client, githubOrg: "test-org"}
				// Missing config and templates must never be used for an archived repo.
				var cfg *config.Config
				var err error
				if command == "managed-files" {
					err = content.CheckFiles("archived-repo", []string{"dependabot"}, cfg, CustomProperties{})
				} else {
					err = content.UpdateLicense("archived-repo", cfg, CustomProperties{})
				}
				if status == http.StatusOK && err != nil {
					t.Fatalf("archived repository should be skipped successfully: %v", err)
				}
				if status != http.StatusOK && err == nil {
					t.Fatal("repository lookup failure must be returned")
				}
				if calls != 1 {
					t.Errorf("got %d API calls, want only the repository lookup", calls)
				}
				if _, err := os.Stat(repoDir("archived-repo")); !os.IsNotExist(err) {
					t.Errorf("repository must not be cloned; stat error: %v", err)
				}
			})
		}
	}
}
