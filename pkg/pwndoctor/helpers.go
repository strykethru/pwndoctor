package pwndoctor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/strykethru/pwndoctor/pkg/pwndoc"
	"github.com/strykethru/pwndoctor/pkg/util"
)

var pwndocAPI *pwndoc.API
var DefaultReportName = "Default Template"

func Init(pwndocURL string) {
	pwndocAPI = pwndoc.New(pwndocURL)

	// maybe can be deleted once everything is migrated
	pwndoc.UseURL(pwndocURL)
}

func AutoAuth() string {
	username, password, totp := GetCredentialToken()
	return Auth(username, password, totp)
}

func Auth(username string, password string, totp string) string {
	return pwndocAPI.Auth(username, password, totp)
}

func GetPwndocAPI() *pwndoc.API {
	return pwndocAPI
}

//goland:noinspection GoUnusedExportedFunction
func SetDefaultReportName(newDefaultName string) {
	DefaultReportName = newDefaultName
}

func CreateInitialUser() string {
	red := color.New(color.FgRed).PrintfFunc()
	initialUserContent, err := util.ReadFile("configs/default/CustomInitialUser.json")
	if err != nil {
		red("\n[-] Error opening file: %s\n", err)
	}

	var customInitialUser pwndoc.APIInitialUser
	err = json.Unmarshal(initialUserContent, &customInitialUser)
	if err != nil {
		red("[-] Error during Unmarshal(): %s\n", err)
	}

	initialUserResponse, err := pwndocAPI.CreateInitialUser(customInitialUser)
	if err != nil {
		red("[-] Error creating initial user: %s\n", err)
	}

	token := fmt.Sprintf("token=JWT%%20%s", initialUserResponse.Data.Token)

	// set the token for future use
	pwndocAPI.Token = token
	return token
}

func CreateLanguages() {
	languageContent, err := util.ReadFile("configs/default/CustomLanguages.json")
	if err != nil {
		log.Fatal("\n[-] Error opening file: ", err)
	}

	var customLanguages []pwndoc.APILanguage
	err = json.Unmarshal(languageContent, &customLanguages)
	if err != nil {
		log.Fatal("Error during Unmarshal(): ", err)
	}

	// Loop through languages
	fmt.Println("\n\n[+] Creating Languages...")
	for i := 0; i < len(customLanguages); i++ {
		fmt.Println("  [+] Creating APILanguage: " + customLanguages[i].Language)

		created, err := pwndocAPI.CreateLanguage(customLanguages[i])
		if err != nil {
			log.Fatalf("Error creating language: %s", err)
		}

		if !created {
			log.Fatalf("Error creating language (really shouldnt get here): %s", customLanguages)
		}
	}
	fmt.Println("[+] Done Creating Languages!")
}

func CreateReportTemplates() {
	fmt.Println("\n[+] Creating Document Templates...")

	templateDir := "templates"
	templateFiles, err := os.ReadDir(templateDir)
	if err != nil {
		log.Fatal(err)
	}

	for _, templateFile := range templateFiles {
		if !strings.HasSuffix(templateFile.Name(), ".docx") {
			continue
		}
		templateFilePath := path.Join(templateDir, templateFile.Name())

		// // Open file
		templateFile, _ := os.Open(templateFilePath)
		fileName := strings.ReplaceAll(filepath.Base(templateFilePath), "-", " ")
		fa := strings.Split(fileName, ".")

		docName := fa[0]

		fmt.Println("  [+] Creating Document APITemplate: " + docName)
		_, err = pwndocAPI.CreateReportTemplate(docName, "docx", templateFile)
		if err != nil {
			log.Fatalf("Error making request: %s", err)
		}
	}

	fmt.Println("[+] Done Creating Document Templates!")
}

func CreateAuditTypes() {
	fmt.Println("\n[+] Creating Audit Types")
	retrievedCustomTemplates, err := pwndocAPI.GetReportTemplates()
	if err != nil {
		log.Fatal("Error getting report templates: ", err)
	}

	var defaultTemplate string
	for _, template := range retrievedCustomTemplates.Data {
		fmt.Println(template.Name)
		if template.Name == DefaultReportName {
			fmt.Printf("\n[+] Found Default Report: %s", template.ID)
			defaultTemplate = template.ID
			break
		}
	}

	// Read opened jsonFile as byte array
	auditContent, err := util.ReadFile("configs/default/CustomAuditTypes.json")
	if err != nil {
		log.Fatal("\n[-] Error opening file: ", err)
	}

	// Unmarshal byte array
	var customAuditTypes []pwndoc.APIAuditType
	err = json.Unmarshal(auditContent, &customAuditTypes)
	if err != nil {
		log.Fatal("Error during Unmarshal(): ", err)
	}

	// // Loop through auditTypes
	fmt.Println("\n[+] Creating Audits...")
	for i := 0; i < len(customAuditTypes); i++ {
		customAuditTypes[i].Templates[0].Template = defaultTemplate

		fmt.Println("  [+] Creating Audit: " + customAuditTypes[i].Name)

		_, err = pwndocAPI.CreateAuditTypes(customAuditTypes[i])
		if err != nil {
			log.Fatalf("Error making request: %s", err)
		}
	}
	fmt.Println("[+] Done Creating Audits!")
}

func CreateVulnerabilityTypes() {
	// Read opened jsonFile as byte array
	vulnerabilityTypeContent, err := util.ReadFile("configs/default/CustomVulnerabilityTypes.json")
	if err != nil {
		log.Fatal("\n[-] Error opening file: ", err)
	}

	// Unmarshal byte array
	var customVulnerabilityTypes []pwndoc.APIVulnerabilityType
	err = json.Unmarshal(vulnerabilityTypeContent, &customVulnerabilityTypes)
	if err != nil {
		log.Fatal("Error during Unmarshal(): ", err)
	}

	// Loop through Vulnerability Types
	fmt.Println("\n[+] Creating Vulnerability Types...")
	for i := 0; i < len(customVulnerabilityTypes); i++ {
		fmt.Println("  [+] Creating APISection: " + customVulnerabilityTypes[i].Name)

		_, err = pwndocAPI.CreateVulnerabilityType(customVulnerabilityTypes[i])
		if err != nil {
			log.Fatalf("Error making request: %s", err)
		}
	}
	fmt.Println("[+] Done Creating Vulnerability Types!")
}

func CreateVulnerabilityCategories() {
	// Read opened jsonFile as byte array
	vulnerabilityCategoryContent, err := util.ReadFile("configs/default/CustomVulnerabilityCategory.json")
	if err != nil {
		log.Fatal("\n[-] Error opening file: ", err)
	}

	// Unmarshal byte array
	var customVulnerabilityCategories []pwndoc.APIVulnerabilityCategory
	err = json.Unmarshal(vulnerabilityCategoryContent, &customVulnerabilityCategories)
	if err != nil {
		log.Fatal("Error during Unmarshal(): ", err)
	}

	// Loop through Vulnerability Categories
	fmt.Println("\n[+] Creating Vulnerability Categories...")
	for i := 0; i < len(customVulnerabilityCategories); i++ {
		fmt.Println("  [+] Creating Vulnerability Category: " + customVulnerabilityCategories[i].Name)

		_, err = pwndocAPI.CreateVulnerabilityCategory(customVulnerabilityCategories[i])
		if err != nil {
			log.Fatalf("Error making request: %s", err)
		}
	}
	fmt.Println("[+] Done Creating Vulnerability Categories!")
}

func CreateSections() {
	// Read opened jsonFile as byte array
	sectionContent, err := util.ReadFile("configs/default/CustomSections.json")
	if err != nil {
		log.Fatal("\n[-] Error opening file: ", err)
	}

	// Unmarshal byte array
	var customSections []pwndoc.APISection
	err = json.Unmarshal(sectionContent, &customSections)
	if err != nil {
		log.Fatal("Error during Unmarshal(): ", err)
	}

	// Loop through sections
	fmt.Println("\n[+] Creating Sections...")
	for i := 0; i < len(customSections); i++ {
		fmt.Println("  [+] Creating APISection: " + customSections[i].Name)
		_, err = pwndocAPI.CreateSection(customSections[i])
		if err != nil {
			log.Fatalf("Error making request: %s", err)
		}
	}
	fmt.Println("[+] Done Creating Sections!")
}

func CreateSectionFields() {
	// Read opened jsonFile as byte array
	sectionFieldsContent, err := util.ReadFile("configs/default/CustomSectionFields.json")
	if err != nil {
		log.Fatal("\n[-] Error opening file: ", err)
	}

	// Unmarshal byte array
	var customSectionFields []pwndoc.APICustomField
	err = json.Unmarshal(sectionFieldsContent, &customSectionFields)
	if err != nil {
		log.Fatal("Error during Unmarshal(): ", err)
	}

	// Loop through Sections Fields
	fmt.Println("\n[+] Creating Sections Fields...")
	for i := 0; i < len(customSectionFields); i++ {
		fmt.Println("  [+] Creating APISection Field: " + customSectionFields[i].DisplaySub)
		_, err = pwndocAPI.CreateCustomField(customSectionFields[i])
		if err != nil {
			log.Fatalf("Error making request: %s", err)
		}
	}
	fmt.Println("[+] Done Creating Sections Fields!")
}

func CreateVulnerabilityFields() {
	// Read opened jsonFile as byte array
	vulnerabilityFieldsContent, err := util.ReadFile("configs/default/CustomVulnerabilityFields.json")
	if err != nil {
		log.Fatal("\n[-] Error opening file: ", err)
	}

	// Unmarshal byte array
	var customVulnerabilityFields []pwndoc.APICustomField
	err = json.Unmarshal(vulnerabilityFieldsContent, &customVulnerabilityFields)
	if err != nil {
		log.Fatal("Error during Unmarshal(): ", err)
	}

	// Loop through vulnerability Fields
	fmt.Println("\n[+] Creating Vulnerability Fields...")
	for i := 0; i < len(customVulnerabilityFields); i++ {
		fmt.Println("  [+] Creating Vulnerability Field: " + customVulnerabilityFields[i].Label)

		_, err = pwndocAPI.CreateCustomField(customVulnerabilityFields[i])
		if err != nil {
			log.Fatalf("Error making request: %s", err)
		}
	}
	fmt.Println("[+] Done Creating Vulnerability Fields!")
}

func CreateVulnerabilities() {
	vulnerabilityContent, err := util.ReadFile("configs/default/CustomVulnerabilities.json")
	if err != nil {
		log.Fatal("\n[-] Error opening file: ", err)
	}
	vulnerabilityContent = bytes.TrimPrefix(vulnerabilityContent, []byte("\xef\xbb\xbf"))

	var vulnerabilities pwndoc.APIVulnerabilities
	err = json.Unmarshal(vulnerabilityContent, &vulnerabilities)
	if err != nil {
		log.Fatal("Error during Unmarshal(): ", err)
	}

	fmt.Println("\n[+] Creating APIVulnerabilities...")
	for i := 0; i < len(vulnerabilities); i++ {
		fmt.Println("  [+] Creating Vulnerability: " + vulnerabilities[i].Details[0].Title)
	}

	_, err = pwndocAPI.CreateVulnerabilities(vulnerabilities)
	if err != nil {
		log.Fatalf("Error making request: %s", err)
	}

	fmt.Println("[+] Done Creating APIVulnerabilities!")
}

func CreateUsers() {
	usersData, err := util.ReadFile("configs/default/CustomUsers.json")
	if err != nil {
		log.Fatal("Error opening users file: ", err)
	}

	var customUsers []pwndoc.APIUser
	err = json.Unmarshal(usersData, &customUsers)
	if err != nil {
		log.Fatal("Error unmarshalling user data: ", err)
	}

	fmt.Println("\n[+] Creating Users...")
	for i := 0; i < len(customUsers); i++ {
		fmt.Println("  [+] Creating APIUser: " + customUsers[i].Username)
	}

	_, err = pwndocAPI.CreateUsers(customUsers)
	if err != nil {
		log.Fatalf("Error making request: %s", err)
	}
	fmt.Println("[+] Done Creating Users!")
}

func CreateSettings() {
	settingsData, err := util.ReadFile("configs/default/CustomSettings.json")
	if err != nil {
		log.Fatal("Error opening users file: ", err)
	}

	var settings pwndoc.APISettings
	err = json.Unmarshal(settingsData, &settings)
	if err != nil {
		log.Fatal("Error unmarshalling settings data: ", err)
	}

	fmt.Println("\n[+] Importing APISettings...")

	_, err = pwndocAPI.CreateSettings(settings)
	if err != nil {
		log.Fatalf("Error making request: %s", err)
	}
	fmt.Println("[+] Done Importing APISettings!")
}

func GetAuditNames() []string {
	audits, err := pwndocAPI.GetAudits()
	if err != nil {
		log.Fatalf("Error getting audits: %s", err)
	}

	var auditNames []string
	for _, audit := range audits.Data {
		auditNames = append(auditNames, audit.Name)
	}
	return auditNames
}
