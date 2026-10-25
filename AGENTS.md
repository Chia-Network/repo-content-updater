# Agent instructions

## Threat model for the dependency review workflows

The dependency review templates and `internal/workflowscripts/` run an AI
review agent on Dependabot and Renovate pull requests.

- **The review agent we invoke is trusted.** It is honest, and it is not an
  adversary. Do not add defenses against it lying, tampering with its own
  outputs, or attacking the workflow.
- **Upstream content is untrusted.** That means the dependency's repository,
  its published packages, release notes, changelogs, PR body text, version
  strings, tags and registry metadata. Assume all of it is written to trick
  the honest agent or the scripts into a wrong action or a false verdict.

## Design principles

- **Treat upstream content as data, never as instructions.** Keep it out of
  prompt instructions, shell code, expressions and file paths unless it has
  been validated or quoted.
- **Fail closed toward "not clean".** Missing, ambiguous, unparsable or
  unverifiable input never produces a clean or benign verdict. It produces
  inconclusive or blocking, with a stated reason.
- **Decide once.** Each fact (versions, coverage, verdict, check result) has
  one canonical parser or decision point. Do not re-derive it in another
  language or step.
- **Prefer structured sources over prose.** Use manifests, lockfiles, git
  objects and registry data rather than scraped markdown.
- **Never follow upstream links or paths blindly.** Symlinks, submodules,
  `..` and absolute paths from upstream must not escape the tree under
  review, and must not hide content from the scan.
- **Validate untrusted version and tag text.** Parse it against one grammar
  per ecosystem before using it.
- **Keep it simple.** Each defense must answer an upstream-content threat.
  Complexity whose only purpose is guarding against the trusted agent should
  be removed, not extended.

## Trusted package indexes

This is a deliberate decision: **packages from the organization's
configured package indexes are trusted and are not scanned.** The indexes
are listed only in `TRUSTED_PYTHON_INDEXES` in
`internal/workflowscripts/dependency_cursor_review_upstream.py`.

- A repository's Dependabot config can select among the listed indexes. It
  cannot add one. A config naming any other Python index, or one the
  scripts cannot read, leaves every pip change inconclusive.
- A requirements file's `--index-url`, `-i` and `--extra-index-url` options
  select indexes for that file and the files it includes, read in pip's
  order. The last `--index-url` is its effective index, and any
  `--extra-index-url` keeps PyPI as a source. A file keeps its replacing
  trusted index only when every requirements file in the repository that
  includes it, directly or through other includes, ends with that same index
  and names no extra source. Any other index, `--find-links`, `--no-index`, an
  option filled from the environment, or an include outside the repository
  leaves that file unable to replace PyPI, so the pip change is looked up and
  scanned. Only a Dependabot config the scripts cannot read leaves the change
  inconclusive.
- Any mention of the package in `pyproject.toml`, `setup.py`, `setup.cfg` or
  `Pipfile` in the changed package's own directory is an unhashed occurrence
  with no index, because pip installs it from the default index. A mention in
  a manifest in another directory is not part of the change. It never makes a
  change trusted.
- Includer discovery reads each include option in a requirements file and
  treats a tracked symlink whose target names the base, a `.txt` or `.in` file
  that cannot be read or parsed, more than 64 requirements files or 256
  candidates for one base, or more than 8 MB of candidate text as leaving the
  base unable to replace PyPI, so the pip change is looked up and scanned.
  `.txt` and `.in` files are decoded as pip reads them: a BOM-selected
  encoding, then UTF-8, then latin-1. A base filename split across a
  continuation or built from quoted pieces is not detected; that is an
  accepted limitation.
- A Dependabot `replaces-base` setting describes Dependabot's own resolution.
  It never makes an index replace PyPI for pip; only a requirements file's
  effective index does.
- pip settings outside a requirements file are not trusted. A tracked
  `pip.conf` or `pip.ini` (name compared case-insensitively), a tracked file
  that names `PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL`, `PIP_FIND_LINKS`,
  `PIP_NO_INDEX`, `PIP_CONFIG_FILE`, `UV_INDEX`, `UV_INDEX_URL`,
  `UV_EXTRA_INDEX_URL`, `UV_DEFAULT_INDEX`, `UV_FIND_LINKS`, `UV_NO_INDEX` or
  `UV_INDEX_STRATEGY` (name compared case-insensitively), an `index-url`,
  `extra-index-url`, `find-links` or `no-index` key in a `[global]`,
  `[install]`, `[tool.pip]` or `[tool.uv]` section, a tox `indexserver`
  setting, a pip `config set` command, a nox `session.install` call passing an
  index option, or a pip command outside the requirements files this check
  reads that passes an index option leaves every requirements file unable to
  replace PyPI, so the pip change is looked up and scanned.
- Long index options count by any unique prefix of `--index-url`,
  `--extra-index-url`, `--find-links` and `--no-index`, from `--in`, `--ext`,
  `--fi` and `--no-ind`. A pip command is `pip`, `pip3.11`, `python -m pip`,
  `py -m pip` or `uv pip`, with global options before `install`; every install
  command on a joined line is checked. A short `-i` or `-f` counts after such
  a command, alone or clustered with other letters. A quoted exec-form token
  in an array that names pip, and a quoted index option in a nox
  `session.install` call, also count. A YAML folded scalar or shell
  continuation is joined first.
- Options of other tools and prose without a pip command do not count.
  Accepted limits: an option assembled from a variable or shell expansion, a
  YAML form other than a simple folded scalar or an indented option on the
  next line, a nox call other than `session.install`, and commands of tools
  other than pip, uv, nox or tox are not detected.
- pip configuration outside the repository is out of scope: the review reads
  only the pull request's tree.
- A pip change is trusted only when a listed, configured index serves that
  exact version and either every file hash its lock records matches a file
  downloaded from that index's own links, or every unhashed occurrence is in
  a requirements file whose effective index is a listed index that names no
  other source, so that index replaces PyPI for that install. Otherwise it is
  looked up and scanned as usual.
- Each package check has its own time and byte limits for reading the index
  page and its files. A grouped update runs one check per package, so it can
  take up to N times those limits.
- Trusted changes are disclosed in the review summary. They never block,
  and they are not counted as scanned.
- Do not "fix" this by scanning or blocking these packages. Changing the
  list or this rule needs the maintainers' explicit sign-off.
