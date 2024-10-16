package cmd

import (
	"log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/chia-network/repo-content-updater/internal/config"
	"github.com/chia-network/repo-content-updater/internal/repo"
)

// licenseCmd represents the license command
var licenseCmd = &cobra.Command{
	Use:   "license",
	Short: "Updates licenses in repos with license flag",
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

		err = content.CheckLicenses(cfg)
		if err != nil {
			log.Fatalln(err.Error())
		}
	},
}

func init() {
	rootCmd.AddCommand(licenseCmd)
}
