package cmd

import (
	"fmt"
	"log"
	"sort"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/chia-network/repo-content-updater/internal/repo"
)

// debugPropertiesCmd prints the resolved CustomProperties for each repo
var debugPropertiesCmd = &cobra.Command{
	Use:   "debug-properties",
	Short: "Prints the resolved custom properties for repos in the org",
	Long: `Fetches GitHub org custom properties and prints the values that
repo-content-updater would use for each repo. Use --repo to inspect a single repo.`,
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

		properties, err := content.GetResolvedProperties(viper.GetString("repo"))
		if err != nil {
			log.Fatalf("Error fetching properties: %s", err.Error())
		}

		if len(properties) == 0 {
			fmt.Println("No repos found.")
			return
		}

		repos := make([]string, 0, len(properties))
		for r := range properties {
			repos = append(repos, r)
		}
		sort.Strings(repos)

		for _, r := range repos {
			props := properties[r]
			fmt.Printf("%s:\n", r)
			fmt.Printf("  bypass-pr: %v\n", props.BypassPR)
		}
	},
}

func init() {
	rootCmd.AddCommand(debugPropertiesCmd)
}
