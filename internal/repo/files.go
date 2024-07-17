package repo

import (
	"context"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/google/go-github/v59/github"

	"github.com/chia-network/repo-content-updater/internal/config"
)

// ManagedFiles updates all managed files in the org with current versions
func (c *Content) ManagedFiles(cfg *config.Config) error {
	// repo: [file, file, file]
	reposToCheck := map[string][]string{}

	opts := &github.ListOptions{
		Page:    0,
		PerPage: 100,
	}
	for {
		opts.Page++
		result, resp, err := c.githubClient.Organizations.ListCustomPropertyValues(context.TODO(), c.githubOrg, opts)
		if err != nil {
			return err
		}

		for _, repo := range result {
			for _, property := range repo.Properties {
				if property.PropertyName == "managed-files" && property.Value != nil {
					reposToCheck[repo.RepositoryName] = []string{}

					var finalFiles []string
					files := strings.Split(*property.Value, ",")
					for _, file := range files {
						file = strings.TrimSpace(file)
						if strings.HasPrefix(file, "group:") {
							group := file[len("group:"):]
							groupFiles, err := cfg.ExpandGroup(group)
							if err != nil {
								log.Printf("Error expanding group %s: %s\n", group, err.Error())
								continue
							}

							finalFiles = append(finalFiles, groupFiles...)
						} else {
							finalFiles = append(finalFiles, file)
						}
					}

					reposToCheck[repo.RepositoryName] = finalFiles
				}
			}
		}

		if resp.NextPage == 0 {
			break
		}
	}

	for repo, files := range reposToCheck {
		log.Printf("Need to check %s\n", repo)
		err := c.CheckFiles(repo, files, cfg)
		if err != nil {
			log.Printf("Error updating %s: %s\n", repo, err.Error())
			continue
		}
	}

	return nil
}

// CheckFiles checks all the files for updates in the repo
func (c *Content) CheckFiles(repoName string, files []string, cfg *config.Config) error {
	defer removeDirIfExists(repoDir(repoName))

	r, w, err := c.cloneRepo(repoName)
	if err != nil {
		return err
	}

	repoConfig, err := c.LoadRepoConfig(repoDir(repoName))
	if err != nil {
		log.Printf("Error loading config for %s: %v\n", repoName, err)
	}

	// If we are targeting a different branch with PRs, then our base also needs to start from that branch
	if repoConfig.PrTargetBranch != nil {
		err = c.checkoutBranch(r, w, *repoConfig.PrTargetBranch)
		if err != nil {
			return err
		}
	}

	branchName := "managed-files"
	err = c.createBranch(r, w, branchName)
	if err != nil {
		return err
	}

	hadChanges := false
	for _, file := range files {
		log.Printf(" - Checking %s\n", file)

		fileinfo := cfg.GetFileInfo(file)
		if fileinfo == nil {
			log.Printf("unknown file %s. Skipping...", file)
			continue
		}

		for _, form := range fileinfo.AlternatePaths {
			// Ignoring errors since these alternate file names may not exist
			removePath := fmt.Sprintf("%s/%s", repoDir(repoName), form)
			_ = os.Remove(removePath)
			_, _ = w.Add(removePath)
		}

		tmplContent, err := os.ReadFile(path.Join(c.templates, fileinfo.TemplateName))
		if err != nil {
			return err
		}
		content, err := ProcessTemplate(tmplContent, repoConfig.VarOverrides)
		if err != nil {
			return err
		}

		// Ensure that the directory exists
		repoPath := fmt.Sprintf("%s/%s", repoDir(repoName), fileinfo.RepoPath)
		dir := filepath.Dir(repoPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}

		err = os.WriteFile(repoPath, content, 0644)
		if err != nil {
			return err
		}

		// Stage the changes
		_, err = w.Add(fileinfo.RepoPath)
		if err != nil {
			return err
		}

		status, err := w.Status()
		if err != nil {
			return err
		}

		if status.IsClean() {
			continue
		}
		hadChanges = true

		var message string
		if repoConfig.CommitPrefix != nil {
			// Dereference the pointer to get the string value
			message = fmt.Sprintf("%s Update %s", *repoConfig.CommitPrefix, file)
		} else {
			// Handle the case where PrTargetBranch is nil
			// For example, use a default message or branch name
			message = fmt.Sprintf("Update %s", file)
		}
		err = c.commit(w, repoName, message)
		if err != nil {
			return err
		}
	}

	repo, _, err := c.githubClient.Repositories.Get(context.TODO(), c.githubOrg, repoName)
	if err != nil {
		return fmt.Errorf("error getting repo info: %w", err)
	}

	var DefaultBranch string
	if repoConfig.PrTargetBranch == nil || *repoConfig.PrTargetBranch == "" {
		DefaultBranch = *repo.DefaultBranch
	} else {
		DefaultBranch = *repoConfig.PrTargetBranch
	}

	if hadChanges {
		return c.pushAndPR(r, repoName, branchName, "Update Managed Files", &pushAndPROptions{
			PrTargetBranch: &DefaultBranch,         // Directly using the pointer from repoConfig
			AssignUsers:    repoConfig.AssignUsers, // Assuming AssignUsers is a slice of strings
			AssignGroup:    repoConfig.AssignGroup, // Directly using the pointer from repoConfig
		})
	}

	return nil
}
