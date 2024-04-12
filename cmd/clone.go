package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/strykethru/pwndoctor/pkg/pwndoctor"
)

var DestinationName string
var cloneCmd = &cobra.Command{
	Use:   "clone",
	Short: "Clone an audit",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		pwndoctor.Init(PwnDocURL)
		pwndoctor.AutoAuth()

		var engagementList []string
		if EngagementName == "" {
			auditNames := pwndoctor.GetAuditNames()
			for _, name := range auditNames {
				fmt.Println(name)
			}
			fmt.Println("Please provide the engagement name(s) you would like to clone with -e")
		}
		if EngagementName != "" {
			engagementList = append(engagementList, strings.Split(EngagementName, ",")...)
			if DestinationName == "" {
				fmt.Println("Please provide the destination audit name with -d")
			}
			if DestinationName != "" {
				pwndoctor.DoClone(engagementList, DestinationName)
			}
		}

	},
}

func init() {
	rootCmd.AddCommand(cloneCmd)
	cloneCmd.Flags().StringVarP(&PwnDocURL, "url", "u", "", "PwnDoc-NG URL (i.e. https://127.0.0.1:8443)")
	cloneCmd.Flags().StringVarP(&EngagementName, "engagement", "e", "", "Engagement Name")
	cloneCmd.Flags().StringVarP(&DestinationName, "destination", "d", "", "Destination Audit Name")
}
