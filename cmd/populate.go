package cmd

import (
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/strykethru/pwndoctor/pkg/pwndoctor"
)

var PwnDocURL string

// csCmd represents the cs command
var csCmd = &cobra.Command{
	Use:   "populate",
	Short: "Populate custom sections",
	Long:  `Subcommand for custom sections.`,
	Run: func(cmd *cobra.Command, args []string) {
		pwndoctor.Init(PwnDocURL)
		green := color.New(color.FgGreen).PrintfFunc()

		initStatus, _ := cmd.Flags().GetBool("init")

		if initStatus {
			//goland:noinspection SpellCheckingInspection
			green("[+] We's Knittin baby!\n")
			pwndoctor.CreateInitialUser()
		} else {
			green("[+] We been knitted baby!\n")
			username, password, totp := pwndoctor.GetCredentialToken()
			pwndoctor.Auth(username, password, totp)
		}

		pwndoctor.CreateLanguages()
		pwndoctor.CreateReportTemplates()
		pwndoctor.CreateAuditTypes()
		pwndoctor.CreateVulnerabilityTypes()
		pwndoctor.CreateVulnerabilityCategories()
		pwndoctor.CreateSections()
		pwndoctor.CreateSectionFields()
		pwndoctor.CreateVulnerabilityFields()
		pwndoctor.CreateVulnerabilities()
		pwndoctor.CreateUsers()
		pwndoctor.CreateSettings()
	},
}

func init() {
	rootCmd.AddCommand(csCmd)

	csCmd.Flags().StringVarP(&PwnDocURL, "url", "u", "", "PwnDoc-NG URL (i.e https://127.0.0.1:8443)")
	csCmd.Flags().BoolP("init", "i", false, "Create initial user")
	//err := csCmd.MarkFlagRequired("region")
	//if err != nil {
	//	log.Fatalf("Something went terribly wrong while marking a flag as required: %s", err)
	//}
}
