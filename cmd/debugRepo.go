package cmd

import (
	"log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/chia-network/repo-content-updater/internal/config"
	"github.com/chia-network/repo-content-updater/internal/repo"
)

// debugRepoCmd allows debugging a single repo
var debugRepoCmd = &cobra.Command{
	Use:   "debug-repo",
	Short: "Processes the given repo for debugging",
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

		err = content.CheckFiles(viper.GetString("repo"), viper.GetStringSlice("file"), cfg)
		if err != nil {
			log.Fatalf("Error checking repo: %s", err.Error())
		}
	},
}

func init() {
	debugRepoCmd.PersistentFlags().String("repo", "", "The repo to debug (ex: chia-blockchain)")
	debugRepoCmd.PersistentFlags().StringSlice("file", nil, "The file(s) to debug in the repo. Use the flag multiple times for multiple files")

	cobra.CheckErr(viper.BindPFlag("repo", debugRepoCmd.PersistentFlags().Lookup("repo")))
	cobra.CheckErr(viper.BindPFlag("file", debugRepoCmd.PersistentFlags().Lookup("file")))

	rootCmd.AddCommand(debugRepoCmd)
}
