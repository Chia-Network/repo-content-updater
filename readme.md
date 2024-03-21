# Repo Content Updater

Manages files across repos in a GitHub org based on [custom properties](https://docs.github.com/en/organizations/managing-organization-settings/managing-custom-properties-for-repositories-in-your-organization). 

## Manage Licenses

`repo-content-updater license --github-token ghp_xxx`

Applies a `LICENSE` template to all repos with the custom property `manage-license` set to `yes`. This is split out from the generic managed files so that the property can be set to required org wide and specific "yes" and "no" options (only) provided in a drop down, ensuring a repo either opts in or out of the license specifically.

## Manage Files

`repo-content-updater managed-files --github-token ghp_xxx`

Looks for the `managed-files` custom property on a repo, and parses out a comma separated list of files/groups to include. Files must be referenced by their name in the config file, and groups should be referenced by their group name, prefixed with `group:`.

For example, the value could be: `group:base,go-test`. This would pull in the base group of files and the go-test file.

### Config Format

```yaml
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

  - name: dep-review
    template_name: dependency-review.yml
    repo_path: .github/workflows/dependency-review.yml
    alternate_paths:
      - .github/workflows/dependency-review.yaml
 ```

`groups` allows combining multiple items from `files` into a single group, making it easier to reference in the custom property

`files` is where every supported template must be listed. 
* `name` is the name to reference the file by in groups or in the custom property.
* `template_name` is the name of the template to use from the supplied templates directory
* `repo_path` is the path within the repo to place the file
* `alternate_paths` is a list of alternate/equivalent paths this template might have been named before being managed. These files will be renamed and updated to the latest version of the template, if present
