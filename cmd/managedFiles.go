package cmd

import (
	"log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/chia-network/repo-content-updater/internal/config"
	"github.com/chia-network/repo-content-updater/internal/repo"
)

// managedFilesCmd represents the managedFiles command
var managedFilesCmd = &cobra.Command{
	Use:   "managed-files",
	Short: "Updates all managed files across the org",
	Run: func(cmd *cobra.Command, args []string) {
		content, err := repo.NewContent(&fs, viper.GetString("github-token"))
		if err != nil {
			log.Fatalf("Error creating content manager: %s", err.Error())
		}

		cfg, err := config.LoadConfig("config.yaml")
		if err != nil {
			log.Fatalf("error loading config: %s\n", err.Error())
		}

		err = content.ManagedFiles(cfg)
		if err != nil {
			log.Fatalln(err.Error())
		}
	},
}

func init() {
	rootCmd.AddCommand(managedFilesCmd)
}
