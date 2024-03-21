package cmd

import (
	"log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/chia-network/repo-content-updater/internal/repo"
)

// licenseCmd represents the license command
var licenseCmd = &cobra.Command{
	Use:   "license",
	Short: "Updates licenses in repos with license flag",
	Run: func(cmd *cobra.Command, args []string) {
		content, err := repo.NewContent(viper.GetString("templates"), viper.GetString("github-token"))
		if err != nil {
			log.Fatalf("Error creating content manager: %s", err.Error())
		}

		err = content.CheckLicenses()
		if err != nil {
			log.Fatalln(err.Error())
		}
	},
}

func init() {
	rootCmd.AddCommand(licenseCmd)
}
