package cmd

import (
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "pwndoctor",
	Short: "Go tool used with pwndoc",
	Long: "Purpose: Populates Custom Sections and Fields\n" +
		"If using KeepassXC, you can now pull your pwndoc credentials from your vault " +
		"using the DBUS secrets service!! Simply add a `pwndoc-credentials` entry to KeepassXC " +
		"with the a JSON object containing your credentials:\n\n" +
		"```\n{\"username\":\"zerocool\",\"password\":\"hunter2\"}\n```\n" +
		"It really is that easy!!",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		PwnDocURL = strings.TrimRight(PwnDocURL, "/")
		return nil
	},
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
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
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.go-pwndoc.yaml)")
	rootCmd.PersistentFlags().StringVarP(&PwnDocURL, "url", "u", "", "PwnDoc-NG URL (i.e https://127.0.0.1:8443)")
	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	//rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
