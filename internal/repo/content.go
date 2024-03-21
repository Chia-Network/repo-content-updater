package repo

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/google/go-github/v59/github"
	"github.com/spf13/viper"
)

// Content the content manager object
type Content struct {
	templates      string
	githubOrg      string
	committerName  string
	committerEmail string
	reviewTeamName string
	githubToken    string
	githubClient   *github.Client
}

// NewContent returns new repo content manager
func NewContent(templates, githubOrg, committerName, committerEmail, reviewTeam, githubToken string) (*Content, error) {
	client := github.NewClient(nil).WithAuthToken(githubToken)
	return &Content{
		templates:      templates,
		githubOrg:      githubOrg,
		committerName:  committerName,
		committerEmail: committerEmail,
		reviewTeamName: reviewTeam,
		githubToken:    githubToken,
		githubClient:   client,
	}, nil
}

func repoDir(repoName string) string {
	return fmt.Sprintf("clones/%s", repoName)
}

func (c *Content) cloneRepo(repoName string) (*git.Repository, *git.Worktree, error) {
	_, err := git.PlainClone(repoDir(repoName), false, &git.CloneOptions{
		URL:          fmt.Sprintf("https://%s@github.com/%s/%s", c.githubToken, c.githubOrg, repoName),
		SingleBranch: true,
		Depth:        1,
	})
	if err != nil {
		return nil, nil, err
	}

	r, err := git.PlainOpen(repoDir(repoName))
	if err != nil {
		return nil, nil, err
	}

	// Get the working directory
	w, err := r.Worktree()
	if err != nil {
		return nil, nil, err
	}

	return r, w, nil
}

func (c *Content) checkoutBranch(r *git.Repository, w *git.Worktree, branchName string) error {
	// Fetch the specific branch from the remote
	err := r.Fetch(&git.FetchOptions{
		RefSpecs: []config.RefSpec{
			config.RefSpec(fmt.Sprintf("+refs/heads/%s:refs/remotes/origin/%s", branchName, branchName)),
		},
		Depth: 1,
	})

	// If there's an error, and it's not because the branch is already up-to-date, return the error
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return fmt.Errorf("error funning fetch: %w", err)
	}

	// Check if the local branch exists; if not, create it to track the remote branch
	localBranchRefName := plumbing.NewBranchReferenceName(branchName)
	_, err = r.Reference(localBranchRefName, false)
	if err != nil {
		// Local branch does not exist, create it
		remoteBranchRef, err := r.Reference(plumbing.NewRemoteReferenceName("origin", branchName), true)
		if err != nil {
			return fmt.Errorf("error finding remote branch: %w", err)
		}

		// Create a new local branch that tracks the remote branch
		err = r.Storer.SetReference(plumbing.NewHashReference(localBranchRefName, remoteBranchRef.Hash()))
		if err != nil {
			return fmt.Errorf("error creating local branch: %w", err)
		}
	}

	// Checkout the new local branch
	checkoutOpts := &git.CheckoutOptions{
		Branch: localBranchRefName,
		Create: false,
	}

	err = w.Checkout(checkoutOpts)
	if err != nil {
		return fmt.Errorf("error running checkout: %w", err)
	}

	// Set up tracking information for the new local branch
	err = r.CreateBranch(&config.Branch{
		Name:   branchName,
		Remote: "origin",
		Merge:  plumbing.ReferenceName(fmt.Sprintf("refs/heads/%s", branchName)),
	})
	if err != nil {
		return fmt.Errorf("error setting up tracking for local branch: %w", err)
	}

	return nil
}

func (c *Content) createBranch(r *git.Repository, w *git.Worktree, branchName string) error {
	// Create a new branch reference
	headRef, err := r.Head()
	if err != nil {
		return err
	}

	refName := plumbing.NewBranchReferenceName(branchName)
	err = r.Storer.SetReference(plumbing.NewHashReference(refName, headRef.Hash()))
	if err != nil {
		return err
	}

	err = w.Checkout(&git.CheckoutOptions{
		Branch: refName,
	})
	if err != nil {
		return err
	}

	return nil
}

func (c *Content) commit(w *git.Worktree, repoName string, message string) error {
	if viper.GetBool("sign-commits") {
		err := signCommit(repoDir(repoName), message)
		if err != nil {
			return fmt.Errorf("error signing commit %w", err)
		}
	} else {
		commitOptions := &git.CommitOptions{
			Author: &object.Signature{
				Name:  c.committerName,
				Email: c.committerEmail,
				When:  time.Now(),
			},
		}
		_, err := w.Commit(message, commitOptions)
		if err != nil {
			return err
		}
	}
	return nil
}

type pushAndPROptions struct {
	PrTargetBranch *string
	AssignUsers    []string
	AssignGroup    *string
}

func (c *Content) pushAndPR(r *git.Repository, repoName, branchName, title string, opts *pushAndPROptions) error {
	if !viper.GetBool("push") {
		log.Println("Skipping push, complete")
		return nil
	}
	// Push the new branch to the remote
	err := r.Push(&git.PushOptions{
		Force: true, // Force push in case there are updates to an old unmerged existing version of this branch
	})
	if err != nil {
		if errors.Is(err, git.NoErrAlreadyUpToDate) {
			return fmt.Errorf("branch was already up to date even though there were changes")
		}
		return err
	}
	fmt.Println("Branch pushed successfully")

	newPR := &github.NewPullRequest{
		Title:               github.String(title),
		Head:                github.String(branchName),
		Base:                opts.PrTargetBranch,
		MaintainerCanModify: github.Bool(true),
	}

	// Create the pull request
	pr, _, err := c.githubClient.PullRequests.Create(context.TODO(), c.githubOrg, repoName, newPR)
	if err != nil {
		return fmt.Errorf("error creating pull request: %s", err)
	}

	log.Printf("PR Link is %s\n", *pr.HTMLURL)

	err = c.ensureGroupMembership(repoName)
	if err != nil {
		return fmt.Errorf("error adding review team to repo: %w", err)
	}

	var teamReviewer []string // Correct type declaration for a slice of strings

	// Check if AssignGroup is specified and not empty
	if opts.AssignGroup != nil && *opts.AssignGroup != "" {
		teamReviewer = []string{*opts.AssignGroup} // Use specified AssignGroup
	} else if len(opts.AssignUsers) == 0 {
		// Fallback to the default team name only if no individual users are specified
		teamReviewer = []string{c.reviewTeamName}
	}
	// Requesting review from the specified team and individual users
	_, _, err = c.githubClient.PullRequests.RequestReviewers(context.TODO(), c.githubOrg, repoName, pr.GetNumber(), github.ReviewersRequest{
		TeamReviewers: teamReviewer,
		Reviewers:     opts.AssignUsers, // Directly use specified individual users
	})
	if err != nil {
		return fmt.Errorf("error requesting reviewers: %w", err)
	}

	return nil
}

func (c *Content) ensureGroupMembership(repoName string) error {
	_, err := c.githubClient.Teams.AddTeamRepoBySlug(context.TODO(), c.githubOrg, c.reviewTeamName, c.githubOrg, repoName, &github.TeamAddTeamRepoOptions{Permission: "push"})
	return err
}

func signCommit(dir string, message string) error {
	cmd := exec.Command("git", "-C", dir, "commit", "-S", "-m", message)
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}

// removeDirIfExists deletes the directory and its contents if it exists.
func removeDirIfExists(dir string) {
	// Check if the directory exists
	if _, err := os.Stat(dir); err == nil {
		// Directory exists, remove it along with its contents
		// Silencing errors, since this is just run on a defer and has nowhere to bubble up to
		_ = os.RemoveAll(dir)
	}
}
