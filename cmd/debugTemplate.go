package cmd

import (
	"log"
	"os"
	"path"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/chia-network/repo-content-updater/internal/repo"
)

// debugTemplateCmd represents the debugTemplate command
var debugTemplateCmd = &cobra.Command{
	Use:   "debug-template",
	Short: "Renders the given template for debugging",
	Run: func(cmd *cobra.Command, args []string) {
		tmplContent, err := os.ReadFile(path.Join(viper.GetString("templates"), args[0]))
		if err != nil {
			log.Fatalln(err.Error())
		}
		content, err := repo.ProcessTemplate(tmplContent, map[string]string{})
		if err != nil {
			log.Fatalln(err.Error())
		}

		log.Println(string(content))
	},
}

func init() {
	rootCmd.AddCommand(debugTemplateCmd)
}
