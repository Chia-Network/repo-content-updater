# Repo Content Updater

Manages files across repos in a GitHub org based on [custom properties](https://docs.github.com/en/organizations/managing-organization-settings/managing-custom-properties-for-repositories-in-your-organization).

Archived repositories are skipped by both the `license` and `managed-files` commands, including targeted `--repo` runs and `debug-repo`. Their custom properties can remain configured; no clone, file update, push, or PR is attempted.

## Manage Licenses

`repo-content-updater license --github-token ghp_xxx`

Applies a `LICENSE` template to all repos with the custom property `manage-license` set to `yes`. This is split out from the generic managed files so that the property can be set to required org wide and specific "yes" and "no" options (only) provided in a drop down, ensuring a repo either opts in or out of the license specifically.

## Manage Files

`repo-content-updater managed-files --github-token ghp_xxx`

Looks for the `managed-files` custom property on a repo, and parses out a comma separated list of files/groups to include. Files must be referenced by their name in the config file, and groups should be referenced by their group name, prefixed with `group:`.

For example, the value could be: `group:base,go-test`. This would pull in the base group of files and the go-test file.

Files listed under `default_files` are applied to every non-archived, non-fork repo whose name does not contain "private" or end in "-dos", even when the repo has no `managed-files` property. The defaults are `dependabot-actions` and `dep-review`. Each default is a bundle: the default file (its root) plus its `companion_files`. The root's `requires_paths` and `adoption_marker` decide for the whole bundle; companions do not carry markers.

- `dependabot-actions` renders the same `dependabot.yml` template as the explicit `dependabot` file, with manifest detection: every detected ecosystem (gomod, pip, npm, cargo, swift, docker, terraform, nuget) is enabled, plus `github-actions`. A repo with only workflows gets an Actions-only config. Docker, terraform and nuget manifests are found anywhere in the tree (outside `.git` and `node_modules`) and each directory that holds one is listed under `directories`; a root `*.sln` covers the whole tree for nuget. `var_overrides` such as `DEPENDABOT_GOMOD_DIRECTORY` or `DEPENDABOT_DOCKER_DIRECTORIES` are honoured. The github-actions entry uses the shared template policy: weekly on Tuesday, ungrouped, reviewers `cameroncooper` and `emlowe`. A marked file is never rewritten in a way that drops an ecosystem, directory or target branch it already configures: update entries the rendered template does not cover are merged in from the existing file, and identical duplicate blocks collapse while two blocks that share a key but configure it differently leave the file untouched. If detection fails for the repository, the default is skipped and an existing file is left as it is (an explicit `dependabot` keeps the full config); if one ecosystem fails, that ecosystem stays enabled.
- `dep-review` ships the dependency review workflow: a license and severity gate plus OSV scanning of the PR's lockfiles, including transitive dependencies.

All defaults require `.github/workflows` containing at least one `.yml`/`.yaml` file. Defaults are adopt-only: an existing root without the adoption marker line (`# <adoption_marker>`) is left untouched; a root carrying the marker is updated in place along with its companions; a new bundle is written only when the root and every companion path are absent. Each default root must declare a unique `adoption_marker`. Prefix an entry with `!` to remove that file from the repo, including a default; for example `!dependabot-actions` or `!dep-review`. Opting out of any member of a default bundle, companions included, drops the whole bundle. Opting out of any file that writes the same repo path also opts out of the default, so `!dependabot` and `!go-dependabot` both opt out of `dependabot-actions`. A default is not added when an explicitly selected file writes the same repo path. Managed paths are only read, removed and written when every parent directory is a real directory inside the checkout.

### Artifact review (opt-in)

`dep-review` remains the default for every eligible repo: it ships the dependency
review license and severity gate plus OSV scanning of the PR's lockfiles,
including transitive dependencies. It is adopt-only: a repo whose existing
`.github/workflows/dependency-review.yml` lacks the adoption marker keeps that
file unless it lists `dep-review` explicitly.

`dependency-artifact-review` is a separate, opt-in workflow. It reviews the
published bytes for npm (`npm_and_yarn`), PyPI (`pip`), Go modules (`gomod`) and
SHA-pinned GitHub Actions (`github_actions`) updates. Other ecosystems are
reported as not reviewed. It is **not** in `default_files`.

To enable it, add `dependency-artifact-review` (or
`group:dependency-artifact-review`) to the repo's `managed-files` property, for
example:

```
group:base,dependency-artifact-review
```

The workflow's publish job id is `dependency-artifact-review`, which no other
managed workflow uses. A repo that opts in can require the
`Dependency Artifact Review / dependency-artifact-review` check without it
colliding with the default dependency review workflow's check.

The agent output must start with one `MALWARE_REVIEW_VERDICT:` line. For a
manual `workflow_dispatch` validation run, supply both `pr_number` and the
`updated_dependencies_json` string that `dependabot/fetch-metadata` reports for
that PR.

## Config Format

```yaml
default_files:
  - dependabot-actions
  - dep-review

groups:
  - name: base
    templates:
      - dep-review

  - name: go
    templates:
      - go-makefile
      - go-dependabot

files:
  - name: go-makefile
    template_name: go-makefile
    repo_path: Makefile

  - name: go-dependabot
    template_name: go-dependabot.yml
    repo_path: .github/dependabot.yml
    alternate_paths:
      - .github/dependabot.yaml

  - name: dependabot-actions
    template_name: dependabot.yml
    repo_path: .github/dependabot.yml
    adoption_marker: repo-content-updater:dependabot-actions
    alternate_paths:
      - .github/dependabot.yaml
    requires_paths:
      - .github/workflows

  - name: dep-review
    template_name: dependency-review.yml
    repo_path: .github/workflows/dependency-review.yml
    adoption_marker: repo-content-updater:dependency-review
    requires_paths:
      - .github/workflows
    alternate_paths:
      - .github/workflows/dependency-review.yaml
```

`groups` allows combining multiple items from `files` into a single group, making it easier to reference in the custom property

`files` is where every supported template must be listed.

`default_files` lists files that are managed on every eligible repo unless the repo opts out with `!<name>` in its `managed-files` property. See above for detection, adoption and bundle rules.

### Managed companion scripts (canonical vs templates)

The dependency-artifact-review workflow ships companion scripts from `templates/` into consumer repos (`.github/scripts/`). **Canonical edit location:** `internal/workflowscripts/*` only (Python modules and the prompt). `make test` and `managed-files` run `sync_malware_formatter_templates.py` first, which **emit** byte-identical mirrors into `templates/` at apply time (formatter tests enforce sync). Generated `templates/github-scripts-init.py`, `templates/dcr-*.py`, `templates/dcr-prompt.md`, and the other sync companions are **gitignored** — do not commit or hand-edit them. The consumer package marker is canonical `internal/workflowscripts/github_scripts_init.py` (synced to `.github/scripts/__init__.py`). **Reviewable in git:** workflow YAML and `templates/GENERATED-FORMATTER-MIRRORS`. Edit canonical copies in `internal/workflowscripts/` only.

The legacy `dependency-cursor-review` bundle is retired. Its workflow and companion scripts are listed in the `dep-review` entry's `retired_paths`, so a sync removes them from repos that still carry them.

- `name` is the name to reference the file by in groups or in the custom property.
- `template_name` is the name of the template to use from the supplied templates directory
- `repo_path` is the path within the repo to place the file
- `alternate_paths` is a list of alternate/equivalent paths this template might have been named before being managed. These files will be renamed and updated to the latest version of the template, if present
- `adoption_marker` is required for every default file and must be unique. A default file is only updated when each existing copy contains the line `# <adoption_marker>`
- `requires_paths` is an optional list of repo-relative paths that must exist for this file to be applied as a default. A required directory must directly contain at least one `.yml` or `.yaml` file. Entries must be non-empty, relative, and must not contain `..`. This field is ignored for explicit selections.

## Bypass PR

Set the `repo-content-updater-bypass-pr` custom property to `true` on a repo to opt into direct commits to the target branch instead of opening a pull request. This property uses GitHub's boolean custom property type. When the property is absent or `false`, the default PR-based workflow is used.

This applies to both the `license` and `managed-files` commands.

## Repo Overrides

If you need to override any of the default settings on a per-repo basis, you can create a [.repo-content-updater.yaml](examples/.repo-content-updater.yaml) file in the root of the repo, and configure any overrides there. It must be present in the default branch of the repo to be loaded.

- `pr_target_branch` is the branch to target PRs against. This is the default branch by default, but if this is overridden in the repo, the branch will be created from and targeted against the supplied branch
- `assign_users` is a list of GitHub users to assign the PR to instead of the default review team. If set, the default review team will not be used. This can be used (if desired) in combination with the `assign_group` field of the repo config file
- `assign_group` is a group to assign the created PRs to. This can be used (if desired) in combination with the `assign_users` field of the repo config file
- `commit_prefix` will set a common prefix on any commits generated by this tool.
- `var_overrides` will override the default values for templates with values supplied here

### Chia Python package index

The shared Dependabot template declares the anonymous `chia-pypi` Python
registry at `https://pypi.chia.net/simple/` and enables it for pip updates.
It also declares and references `chia-downloads` at
`https://download.chia.net/simple/`: the index links wheel files and redirects
missing package lookups to that host. Both hosts must be allowed by Dependabot's
proxy. The downloads host serves files, not a browsable package index; it is
declared so those requests are allowed.
Public PyPI remains available; no credentials or per-repository override are
required. Dependabot requires registries to be declared in its own configuration
to allow network access, even when they do not require authentication. Listing
`registries` on a pip update disables manifest code execution, so that entry
sets `insecure-external-code-execution: allow`. See
[GitHub's registry access documentation](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/manage-your-dependency-security/configure-access-to-private-registries)
and [`insecure-external-code-execution`](https://docs.github.com/en/code-security/dependabot/dependabot-version-updates/configuration-options-for-the-dependabot.yml-file#insecure-external-code-execution).
