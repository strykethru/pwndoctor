/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/strykethru/pwndoctor/pkg/pwndoctor"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "lists things in pwndoc",
	Long:  `lists different things in pwndoc, such as: audits, vulnerabilities, findings`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var listAuditsCmd = &cobra.Command{
	Use:   "audits",
	Short: "lists audits in pwndoc",
	Long:  `lists audits in pwndoc`,
	Run: func(cmd *cobra.Command, args []string) {
		// fmt.Println("URL:", PwnDocURL)

		pwndoctor.Init(PwnDocURL)
		username, password, totp := pwndoctor.GetCredentialToken()
		pwndoctor.Auth(username, password, totp)
		auditNames := pwndoctor.GetAuditNames()
		for _, name := range auditNames {
			fmt.Println(name)
		}
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
	listCmd.AddCommand(listAuditsCmd)
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// listCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// listCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
