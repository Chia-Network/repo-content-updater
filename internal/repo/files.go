package repo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/google/go-github/v59/github"

	"github.com/chia-network/repo-content-updater/internal/config"
)

type repoCheck struct {
	name      string
	repo      *github.Repository
	selection config.ManagedFileSelection
	props     CustomProperties
}

// FileModeForContent is 0755 for shebang scripts so consumer linters that
// require an executable bit (ruff EXE001) pass. Other managed files stay 0644.
func FileModeForContent(content []byte) os.FileMode {
	if bytes.HasPrefix(content, []byte("#!")) {
		return 0o755
	}
	return 0o644
}

// writeManagedContent creates parent directories and writes content.
// os.WriteFile leaves the mode of an existing file unchanged, so Chmod applies
// the shebang bit on updates as well as creates.
func writeManagedContent(repoPath string, content []byte) error {
	dir := filepath.Dir(repoPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	mode := FileModeForContent(content)
	if err := os.WriteFile(repoPath, content, mode); err != nil {
		return err
	}
	return os.Chmod(repoPath, mode)
}

// ManagedFiles updates all managed files in the org with current versions.
// The repository listing defines which repos are considered; custom properties
// provide the explicit selections for those repos.
func (c *Content) ManagedFiles(cfg *config.Config, onlyRepo string) error {
	properties, err := c.loadRepoProperties(onlyRepo)
	if err != nil {
		return err
	}

	repositories, err := c.repoUniverse(onlyRepo)
	if err != nil {
		log.Printf(
			"Error listing repositories for %s; continuing with explicit selections only: %s\n",
			c.githubOrg,
			err,
		)
		repositories = nil
	}

	for _, check := range repoChecks(cfg, onlyRepo, repositories, properties) {
		files := filesForRepo(check.selection, check.repo)
		if len(files) == 0 {
			continue
		}
		log.Printf("Need to check %s\n", check.name)
		if err := c.checkSelectedFiles(check.name, files, cfg, check.props); err != nil {
			log.Printf("Error updating %s: %s\n", check.name, err.Error())
		}
	}

	return nil
}

func (c *Content) repoUniverse(onlyRepo string) ([]*github.Repository, error) {
	if onlyRepo != "" {
		repo, _, err := ghDo(func() (*github.Repository, *github.Response, error) {
			return c.githubClient.Repositories.Get(context.TODO(), c.githubOrg, onlyRepo)
		})
		if err != nil {
			return nil, err
		}
		return []*github.Repository{repo}, nil
	}
	return c.listOrgRepositories()
}

func repoChecks(
	cfg *config.Config,
	onlyRepo string,
	repositories []*github.Repository,
	properties map[string]repoPropertyEntry,
) []repoCheck {
	if repositories != nil {
		checks := make([]repoCheck, 0, len(repositories))
		for _, repo := range repositories {
			name := repo.GetName()
			if onlyRepo != "" && !strings.EqualFold(name, onlyRepo) {
				continue
			}
			property := properties[strings.ToLower(name)]
			checks = append(checks, repoCheck{
				name:      name,
				repo:      repo,
				selection: cfg.ResolveManagedFileSelection(name, property.managedFiles),
				props:     property.props,
			})
		}
		return checks
	}

	checks := make([]repoCheck, 0, len(properties))
	for key, property := range properties {
		if onlyRepo != "" && key != strings.ToLower(onlyRepo) {
			continue
		}
		checks = append(checks, repoCheck{
			name:      property.name,
			selection: cfg.ResolveManagedFileSelection(property.name, property.managedFiles),
			props:     property.props,
		})
	}
	return checks
}

func (c *Content) listOrgRepositories() ([]*github.Repository, error) {
	repos := make([]*github.Repository, 0)
	opts := &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{
			Page:    0,
			PerPage: 100,
		},
	}
	for {
		opts.Page++
		page, resp, err := ghDo(func() ([]*github.Repository, *github.Response, error) {
			return c.githubClient.Repositories.ListByOrg(context.TODO(), c.githubOrg, opts)
		})
		if err != nil {
			return nil, err
		}
		repos = append(repos, page...)
		if resp.NextPage == 0 {
			break
		}
	}
	return repos, nil
}

// defaultFilesEligible reports whether a repo may receive default files. Nil
// metadata, archived repos, forks, names containing "private", and names
// ending in "-dos" are ineligible.
func defaultFilesEligible(repo *github.Repository) bool {
	if repo == nil || repo.GetArchived() || repo.GetFork() {
		return false
	}
	name := strings.ToLower(repo.GetName())
	return !strings.Contains(name, "private") && !strings.HasSuffix(name, "-dos")
}

// filesForRepo applies default-file eligibility to a repo. Explicit selections
// are always kept; defaults are only added when defaultFilesEligible is true.
func filesForRepo(selection config.ManagedFileSelection, repo *github.Repository) []config.SelectedFile {
	files := make([]config.SelectedFile, 0, len(selection.Explicit)+len(selection.Defaults))
	for _, name := range selection.Explicit {
		files = append(files, config.SelectedFile{Name: name, Origin: config.OriginExplicit})
	}
	if defaultFilesEligible(repo) {
		for _, name := range selection.Defaults {
			files = append(files, config.SelectedFile{Name: name, Origin: config.OriginDefault})
		}
	}
	return files
}

// CheckFiles checks all the files for updates in the repo
func (c *Content) CheckFiles(repoName string, files []string, cfg *config.Config, props CustomProperties) error {
	var err error
	files, err = cfg.EnsureCompanionFiles(files)
	if err != nil {
		return fmt.Errorf("error ensuring companion files for %s: %w", repoName, err)
	}

	selected := make([]config.SelectedFile, 0, len(files))
	for _, name := range files {
		selected = append(selected, config.SelectedFile{Name: name, Origin: config.OriginExplicit})
	}
	return c.checkSelectedFiles(repoName, selected, cfg, props)
}

func (c *Content) checkSelectedFiles(repoName string, files []config.SelectedFile, cfg *config.Config, props CustomProperties) error {
	defer removeDirIfExists(repoDir(repoName))

	r, w, err := c.cloneRepo(repoName)
	if err != nil {
		return err
	}

	repoConfig, err := c.LoadRepoConfig(repoDir(repoName))
	if err != nil {
		log.Printf("Error loading config for %s: %v\n", repoName, err)
	}

	headRef, err := r.Head()
	if err != nil {
		return fmt.Errorf("error getting head ref for %s: %w", repoName, err)
	}
	headRefName := headRef.Name()
	if !headRefName.IsBranch() {
		return errors.New("HEAD ref is not a branch")
	}
	defaultBranch := headRefName.Short()

	// If we are targeting a different branch with PRs, then our base also needs to start from that branch
	if repoConfig.PrTargetBranch != nil && *repoConfig.PrTargetBranch != defaultBranch {
		err = c.checkoutBranch(r, w, *repoConfig.PrTargetBranch)
		if err != nil {
			return fmt.Errorf("error checking out branch %s: %w", *repoConfig.PrTargetBranch, err)
		}
	}

	branchName := "managed-files"
	err = c.createBranch(r, w, branchName)
	if err != nil {
		return err
	}

	hadChanges := false
	for _, selected := range files {
		file := selected.Name
		log.Printf(" - Checking %s\n", file)

		fileinfo := cfg.GetFileInfo(file)
		if fileinfo == nil {
			log.Printf("unknown file %s. Skipping...", file)
			continue
		}

		content, skip, err := c.prepareManagedFile(repoName, fileinfo, selected.Origin, cfg, repoConfig)
		if err != nil {
			return err
		}
		if skip {
			continue
		}

		for _, form := range fileinfo.AlternatePaths {
			// Ignoring errors since these alternate file names may not exist
			removePath := fmt.Sprintf("%s/%s", repoDir(repoName), form)
			_ = os.Remove(removePath)
			_, _ = w.Add(form)
		}

		repoPath := fmt.Sprintf("%s/%s", repoDir(repoName), fileinfo.RepoPath)
		if err := writeManagedContent(repoPath, content); err != nil {
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

	repo, _, err := ghDo(func() (*github.Repository, *github.Response, error) {
		return c.githubClient.Repositories.Get(context.TODO(), c.githubOrg, repoName)
	})
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
			PrTargetBranch: &DefaultBranch,
			AssignUsers:    repoConfig.AssignUsers,
			AssignGroup:    repoConfig.AssignGroup,
			BypassPR:       props.BypassPR,
		})
	}

	return nil
}

const managedFileMarker = "managed by the repo-content-updater"

// containsTrimmedLine reports whether content contains want as a complete line,
// ignoring surrounding whitespace.
func containsTrimmedLine(content, want string) bool {
	want = strings.TrimSpace(want)
	if want == "" {
		return false
	}
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}

// shouldAdoptExistingFile reports whether a default file may be written. A
// default file is written when no file exists at repo_path or an alternate_path,
// or when every existing file carries the file's adoption marker line. A file
// without an adoption marker is only written when it is absent.
func (c *Content) shouldAdoptExistingFile(repoName string, fileinfo *config.File) (bool, error) {
	marker := strings.TrimSpace(fileinfo.AdoptionMarker)
	want := "# " + marker

	paths := append([]string{fileinfo.RepoPath}, fileinfo.AlternatePaths...)
	for _, repoPath := range paths {
		content, err := os.ReadFile(filepath.Join(repoDir(repoName), filepath.FromSlash(repoPath)))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, err
		}
		if marker == "" || !containsTrimmedLine(string(content), want) {
			return false, nil
		}
	}
	return true, nil
}

// requiredPathExists reports whether repoRelPath exists under root. A directory
// only satisfies the requirement when it directly contains a .yml or .yaml file.
func requiredPathExists(root, repoRelPath string) (bool, error) {
	fullPath := filepath.Join(root, filepath.FromSlash(repoRelPath))
	info, err := os.Stat(fullPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() {
		return true, nil
	}

	entries, err := os.ReadDir(fullPath)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		switch strings.ToLower(filepath.Ext(entry.Name())) {
		case ".yml", ".yaml":
			return true, nil
		}
	}
	return false, nil
}

// firstMissingRequiredPath returns the first requires_paths entry that is not
// satisfied under root, or "" when every entry is satisfied.
func firstMissingRequiredPath(root string, requiredPaths []string) (string, error) {
	for _, requiredPath := range requiredPaths {
		exists, err := requiredPathExists(root, requiredPath)
		if err != nil {
			return "", err
		}
		if !exists {
			return requiredPath, nil
		}
	}
	return "", nil
}

// prepareManagedFile applies per-file selection and template policy, returning
// skip=true when the file should be left untouched.
func (c *Content) prepareManagedFile(repoName string, fileinfo *config.File, origin config.FileOrigin, cfg *config.Config, repoConfig Config) ([]byte, bool, error) {
	if origin == config.OriginDefault {
		missing, err := firstMissingRequiredPath(repoDir(repoName), fileinfo.RequiresPaths)
		if err != nil {
			return nil, false, err
		}
		if missing != "" {
			log.Printf("Skipping default %s for %s: required path %s missing\n", fileinfo.Name, repoName, missing)
			return nil, true, nil
		}

		adopt, err := c.shouldAdoptExistingFile(repoName, fileinfo)
		if err != nil {
			return nil, false, err
		}
		if !adopt {
			log.Printf("Skipping %s for %s: existing file does not carry the adoption marker\n", fileinfo.Name, repoName)
			return nil, true, nil
		}
	}

	tmplContent, err := os.ReadFile(path.Join(c.templates, fileinfo.TemplateName))
	if err != nil {
		return nil, false, err
	}

	templateVars, templateOverrides, err := templateInputsForFile(fileinfo, repoName, cfg, repoConfig)
	if err != nil {
		if origin == config.OriginDefault {
			log.Printf("Skipping default %s for %s: template inputs failed: %v\n", fileinfo.Name, repoName, err)
			return nil, true, nil
		}
		if errors.Is(err, errNoDependabotEcosystems) {
			log.Printf("No Dependabot ecosystems detected for %s; keeping full configuration\n", repoName)
		} else {
			log.Printf("Error inspecting Dependabot manifests for %s; keeping full configuration: %v\n", repoName, err)
		}
	}

	content, err := ProcessTemplate(tmplContent, templateVars, templateOverrides)
	if err != nil {
		return nil, false, err
	}
	return content, false, nil
}

// templateInputsForFile keeps template-specific variable derivation out of the
// managed-file loop. Dependabot flags are detected from the cloned repo, so
// its overrides are already merged into the returned variables.
func templateInputsForFile(fileinfo *config.File, repoName string, cfg *config.Config, repoConfig Config) (map[string]string, map[string]string, error) {
	if fileinfo.TemplateName != dependabotTemplateName {
		return cfg.Variables, repoConfig.VarOverrides, nil
	}
	vars, err := DependabotVarsForRepo(repoDir(repoName), cfg.Variables, repoConfig.VarOverrides)
	return vars, nil, err
}
