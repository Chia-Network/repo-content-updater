package cmd

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/chia-network/repo-content-updater/internal/config"
	"github.com/chia-network/repo-content-updater/internal/repo"
)

func syncFormatterTemplatesFromConfig(configPath string) {
	absConfig, err := filepath.Abs(configPath)
	if err != nil {
		return
	}
	repoRoot := filepath.Dir(absConfig)
	script := filepath.Join(repoRoot, "internal", "workflowscripts", "sync_malware_formatter_templates.py")
	if _, err := os.Stat(script); err != nil {
		return
	}
	cmd := exec.Command("python3", script)
	cmd.Dir = repoRoot
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("formatter template sync failed: %s", err)
	}
}

// managedFilesCmd represents the managedFiles command
var managedFilesCmd = &cobra.Command{
	Use:   "managed-files",
	Short: "Updates all managed files across the org",
	Run: func(cmd *cobra.Command, args []string) {
		content, err := repo.NewContent(
			viper.GetString("templates"),
			viper.GetString("github-org"),
			viper.GetString("committer-name"),
			viper.GetString("committer-email"),
			viper.GetString("review-team"),
			viper.GetString("github-token"),
		)
		if err != nil {
			log.Fatalf("Error creating content manager: %s", err.Error())
		}

		cfg, err := config.LoadConfig(viper.GetString("config"))
		if err != nil {
			log.Fatalf("error loading config: %s\n", err.Error())
		}

		syncFormatterTemplatesFromConfig(viper.GetString("config"))

		err = content.ManagedFiles(cfg, viper.GetString("repo"))
		if err != nil {
			log.Fatalln(err.Error())
		}
	},
}

func init() {
	rootCmd.AddCommand(managedFilesCmd)
}
