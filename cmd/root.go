package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "repo-content-updater",
	Short: "Keeps known files in a repo up to date",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	var (
		cfgFile        string
		templateDir    string
		githubOrg      string
		committerName  string
		committerEmail string
		reviewTeamName string
		githubToken    string
		signCommits    bool
		push           bool
	)

	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "config.yaml", "template config file (default is config.yaml)")
	rootCmd.PersistentFlags().StringVar(&templateDir, "templates", "templates", "Path to templates defined in the config. Defaults to ./templates")
	rootCmd.PersistentFlags().StringVar(&githubOrg, "github-org", "Chia-Network", "The org to process")
	rootCmd.PersistentFlags().StringVar(&committerName, "committer-name", "Chia Automation", "The git user to use when making commits")
	rootCmd.PersistentFlags().StringVar(&committerEmail, "committer-email", "automation@chia.net", "The git email to use when making commits")
	rootCmd.PersistentFlags().StringVar(&reviewTeamName, "review-team", "content-updater-reviewers", "The default team to assigned to the PRs if a repo override is not set")
	rootCmd.PersistentFlags().StringVar(&githubToken, "github-token", "", "The token to use to auth to GitHub API and Push to Repos")
	rootCmd.PersistentFlags().BoolVar(&signCommits, "sign-commits", true, "Whether or not to sign commits")
	rootCmd.PersistentFlags().BoolVar(&push, "push", true, "Whether or not to push and create the pull request")

	cobra.CheckErr(viper.BindPFlag("config", rootCmd.PersistentFlags().Lookup("config")))
	cobra.CheckErr(viper.BindPFlag("templates", rootCmd.PersistentFlags().Lookup("templates")))
	cobra.CheckErr(viper.BindPFlag("github-org", rootCmd.PersistentFlags().Lookup("github-org")))
	cobra.CheckErr(viper.BindPFlag("committer-name", rootCmd.PersistentFlags().Lookup("committer-name")))
	cobra.CheckErr(viper.BindPFlag("committer-email", rootCmd.PersistentFlags().Lookup("committer-email")))
	cobra.CheckErr(viper.BindPFlag("review-team", rootCmd.PersistentFlags().Lookup("review-team")))
	cobra.CheckErr(viper.BindPFlag("github-token", rootCmd.PersistentFlags().Lookup("github-token")))
	cobra.CheckErr(viper.BindPFlag("sign-commits", rootCmd.PersistentFlags().Lookup("sign-commits")))
	cobra.CheckErr(viper.BindPFlag("push", rootCmd.PersistentFlags().Lookup("push")))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	// Find home directory.
	home, err := os.UserHomeDir()
	cobra.CheckErr(err)

	// Search config in home directory with name ".repo-content-updater" (without extension).
	viper.AddConfigPath(home)
	viper.SetConfigType("yaml")
	viper.SetConfigName(".repo-content-updater")
	viper.SetEnvPrefix("REPO_CONTENT_UPDATER")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
