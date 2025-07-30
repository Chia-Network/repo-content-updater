package cmd

import (
	"log"
	"os"
	"path"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/chia-network/repo-content-updater/internal/config"
	"github.com/chia-network/repo-content-updater/internal/repo"
)

// debugTemplateCmd represents the debugTemplate command
var debugTemplateCmd = &cobra.Command{
	Use:   "debug-template",
	Short: "Renders the given template for debugging",
	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := config.LoadConfig(viper.GetString("config"))
		if err != nil {
			log.Fatalf("error loading config: %s\n", err.Error())
		}

		tmplContent, err := os.ReadFile(path.Join(viper.GetString("templates"), args[0]))
		if err != nil {
			log.Fatalln(err.Error())
		}
		content, err := repo.ProcessTemplate(
			tmplContent,
			cfg.Variables,
			viper.GetStringMapString("debug-template-vars"),
		)
		if err != nil {
			log.Fatalln(err.Error())
		}

		log.Println(string(content))
	},
}

func init() {
	debugTemplateCmd.PersistentFlags().StringToString("var", map[string]string{}, "Set override vars for the template")
	cobra.CheckErr(viper.BindPFlag("debug-template-vars", debugTemplateCmd.PersistentFlags().Lookup("var")))

	rootCmd.AddCommand(debugTemplateCmd)
}
