package pwndoctor

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/defektive/secrets"
	"github.com/fatih/color"
	"github.com/strykethru/pwndoctor/pkg/pwndoc"
	"github.com/strykethru/pwndoctor/pkg/util"
	"golang.org/x/term"
	"os"
	"strings"
	"syscall"
)

func GetCredentialsFromPwndocJSON() (pwndoc.APILogin, error) {
	var pwndocCredentials pwndoc.APILogin
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return pwndocCredentials, err
	}

	pwndocCredFile := fmt.Sprintf("%s/pwndoc.json", homeDir)
	doesFileExist, err := util.CheckForFile(pwndocCredFile)
	if err != nil {
		return pwndocCredentials, err
	}

	if !doesFileExist {
		return pwndocCredentials, errors.New("unable to load pwndoc.json file not found")
	}

	pwndocCredContent, err := util.ReadFile(pwndocCredFile)
	if err != nil {
		return pwndocCredentials, err
	}
	err = json.Unmarshal(pwndocCredContent, &pwndocCredentials)

	return pwndocCredentials, err
}

func GetCredentialsFromSecretsService() (pwndoc.APILogin, error) {
	credentials := pwndoc.APILogin{}

	credentialsStr := secrets.GetSecret("pwndoc-credentials")
	if len(credentialsStr) > 0 {
		err := json.Unmarshal([]byte(credentialsStr), &credentials)
		if err == nil {
			// it worked
			if len(credentials.Password) > 0 && len(credentials.Username) > 0 {
				return credentials, nil
			}
		}
	}

	return credentials, errors.New("unable to load credentials from secrets service")
}

func GetCredentialToken() (string, string, string) {

	credentials, err := GetCredentialsFromSecretsService()
	if err == nil && credentials.Username != "" && credentials.Password != "" {
		return credentials.Username, credentials.Password, "any"
	}

	credentials, err = GetCredentialsFromPwndocJSON()
	if err == nil && credentials.Username != "" && credentials.Password != "" {
		return credentials.Username, credentials.Password, "any"
	}

	red := color.New(color.FgRed).PrintfFunc()
	blue := color.New(color.FgBlue).PrintfFunc()

	reader := bufio.NewReader(os.Stdin)
	blue("  [*] Enter Username: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		red("[-] Error reading username: %s\n", err)
		os.Exit(0)
	}

	blue("  [*] Enter Password: ")
	bytePassword, err := term.ReadPassword(syscall.Stdin)
	if err != nil {
		red("[-] Error reading password: %s\n", err)
		os.Exit(0)
	}

	password := string(bytePassword)
	return strings.TrimSpace(username), strings.TrimSpace(password), "any"
}
