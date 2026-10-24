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
		if len(files.Explicit) == 0 && len(files.Defaults) == 0 {
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
// are always kept; default bundles are only kept when defaultFilesEligible is
// true.
func filesForRepo(selection config.ManagedFileSelection, repo *github.Repository) config.ManagedFileSelection {
	if !defaultFilesEligible(repo) {
		selection.Defaults = nil
	}
	return selection
}

// CheckFiles checks all the files for updates in the repo
func (c *Content) CheckFiles(repoName string, files []string, cfg *config.Config, props CustomProperties) error {
	files, err := cfg.EnsureCompanionFiles(files)
	if err != nil {
		return fmt.Errorf("error ensuring companion files for %s: %w", repoName, err)
	}

	return c.checkSelectedFiles(repoName, config.ManagedFileSelection{Explicit: files}, cfg, props)
}

func (c *Content) checkSelectedFiles(repoName string, selection config.ManagedFileSelection, cfg *config.Config, props CustomProperties) error {
	repo, err := c.repoMetadata(repoName)
	if err != nil {
		return err
	}
	if repo.GetArchived() {
		log.Printf("Skipping archived repository %s\n", repoName)
		return nil
	}

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
	err = c.applySelection(repoName, selection, cfg, repoConfig, func(file string, repoPaths []string) error {
		if _, err := w.Add(repoPaths[0]); err != nil {
			return err
		}
		for _, removed := range repoPaths[1:] {
			// A removed path that never existed has nothing to stage.
			_, _ = w.Add(removed)
		}
		status, err := w.Status()
		if err != nil || status.IsClean() {
			return err
		}
		hadChanges = true
		message := fmt.Sprintf("Update %s", file)
		if repoConfig.CommitPrefix != nil {
			message = fmt.Sprintf("%s Update %s", *repoConfig.CommitPrefix, file)
		}
		return c.commit(w, repoName, message)
	})
	if err != nil {
		return err
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

// stageFunc stages one written managed file. repoPaths starts with the file's
// repo_path, followed by the alternate and retired paths that were removed.
type stageFunc func(file string, repoPaths []string) error

// applySelection writes a repo's managed files into its checkout without
// touching GitHub: explicit files, then the files of every adoptable default
// bundle. stage runs after each file is written.
func (c *Content) applySelection(repoName string, selection config.ManagedFileSelection, cfg *config.Config, repoConfig Config, stage stageFunc) error {
	defaults, err := adoptableDefaults(repoName, selection.Defaults, cfg)
	if err != nil {
		return err
	}
	files := make([]config.SelectedFile, 0, len(selection.Explicit)+len(defaults))
	for _, name := range selection.Explicit {
		files = append(files, config.SelectedFile{Name: name, Origin: config.OriginExplicit})
	}
	files = append(files, defaults...)

	// Render and confine every file before touching the checkout, so a path
	// problem in any file leaves the whole checkout unchanged.
	type plannedWrite struct {
		name     string
		fileinfo *config.File
		content  []byte
	}
	planned := make([]plannedWrite, 0, len(files))
	for _, selected := range files {
		log.Printf(" - Checking %s\n", selected.Name)
		fileinfo := cfg.GetFileInfo(selected.Name)
		if fileinfo == nil {
			log.Printf("unknown file %s. Skipping...", selected.Name)
			continue
		}
		content, err := c.renderManagedFile(repoName, selected, fileinfo, cfg, repoConfig)
		if errors.Is(err, errSkipManagedFile) {
			log.Printf("Skipping %s for %s: %v\n", selected.Name, repoName, err)
			continue
		}
		if err != nil {
			return err
		}
		for _, repoRelPath := range writtenPaths(fileinfo) {
			if _, err := confinedPath(repoDir(repoName), repoRelPath); err != nil {
				return err
			}
		}
		planned = append(planned, plannedWrite{name: selected.Name, fileinfo: fileinfo, content: content})
	}

	for _, write := range planned {
		written := writtenPaths(write.fileinfo)
		if err := removeConfined(repoDir(repoName), removedPaths(write.fileinfo)); err != nil {
			return err
		}
		repoPath, err := managedWritePath(repoDir(repoName), write.fileinfo.RepoPath)
		if err != nil {
			return err
		}
		if err := writeManagedContent(repoPath, write.content); err != nil {
			return err
		}
		if err := stage(write.name, written); err != nil {
			return err
		}
	}
	return nil
}

// errSkipManagedFile marks a file that is not written this run, so the
// existing copy stays as it is; the wrapping error says why.
var errSkipManagedFile = errors.New("keeping the existing file")

// renderManagedFile renders fileinfo's template for repoName and finishes it
// with postRenderForFile. When the template inputs cannot be derived, an
// explicit file renders from the fallback inputs and a default file is
// skipped with an error wrapping errSkipManagedFile, so an adopted file stays
// as it is.
func (c *Content) renderManagedFile(repoName string, selected config.SelectedFile, fileinfo *config.File, cfg *config.Config, repoConfig Config) ([]byte, error) {
	tmplContent, err := os.ReadFile(path.Join(c.templates, fileinfo.TemplateName))
	if err != nil {
		return nil, err
	}

	templateVars, templateOverrides, err := templateInputsForFile(fileinfo, repoName, cfg, repoConfig)
	if err != nil {
		if selected.Origin == config.OriginDefault {
			return nil, fmt.Errorf("%w: template inputs failed: %w", errSkipManagedFile, err)
		}
		log.Printf("Template inputs for %s in %s failed; rendering the full template: %v\n", selected.Name, repoName, err)
	}

	content, err := ProcessTemplate(tmplContent, templateVars, templateOverrides)
	if err != nil {
		return nil, err
	}
	return postRenderForFile(repoDir(repoName), selected, fileinfo, content)
}

// templateInputsForFile keeps template-specific variable derivation out of the
// managed-file loop. Dependabot flags are detected from the cloned repo, so
// its overrides are already merged into the returned variables.
func templateInputsForFile(fileinfo *config.File, repoName string, cfg *config.Config, repoConfig Config) (map[string]string, map[string]string, error) {
	vars, overrides := cfg.Variables, repoConfig.VarOverrides
	var err error
	if fileinfo.TemplateName == dependabotTemplateName {
		vars, err = DependabotVarsForRepo(repoDir(repoName), cfg.Variables, repoConfig.VarOverrides)
		overrides = nil
	}
	return withAdoptionMarker(vars, fileinfo.AdoptionMarker), overrides, err
}

// postRenderForFile finishes rendered template output for fileinfo, the
// counterpart of templateInputsForFile. Only the Dependabot file is changed
// (see postRenderDependabot); a default that must keep its existing file
// returns an error wrapping errSkipManagedFile.
func postRenderForFile(dir string, selected config.SelectedFile, fileinfo *config.File, rendered []byte) ([]byte, error) {
	if fileinfo.TemplateName != dependabotTemplateName {
		return rendered, nil
	}
	return postRenderDependabot(dir, selected.Origin == config.OriginDefault, fileinfo, rendered)
}
