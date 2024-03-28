package pwndoctor

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"

	"github.com/strykethru/pwndoctor/pkg/pwndoc"
)

const MongoDBDockerExport = "docker exec -i mongo-pwndoc-ng /usr/bin/mongodump --uri=mongodb://127.0.0.1/pwndoc --archive"

func DoExport(includeAuditNames []string, pwndocSSHUser string, pwndocSSHHost string) {

	allAudits, err := pwndocAPI.GetAudits()
	if err != nil {
		fmt.Printf("Error getting audits from pwndoc: %s", err)
	}

	if len(includeAuditNames) == 0 {
		retrievedAudits, err := pwndocAPI.GetAudits()
		if err != nil {
			log.Fatal("Error reading response body (AUDITS): ", err)
		}

		for _, data := range retrievedAudits.Data {
			includeAuditNames = append(includeAuditNames, data.Name)
		}
	}

	//////////////////////////////////////////////
	// THIS IS WHERE WE GET CURRENT ENGAGEMENTS //
	//////////////////////////////////////////////

	for _, audit := range allAudits.Data {
		if len(includeAuditNames) > 0 {
			isAuditIncluded := false
			for _, auditName := range includeAuditNames {
				if audit.Name == auditName {
					isAuditIncluded = true
					break
				}
			}
			if !isAuditIncluded {
				continue
			}
		}

		fmt.Println("[+] Audit ID: ", audit.ID)
		fmt.Println("[+] Exporting Audit info...")

		dirList := []string{"audit-findings", "images", "report"}
		for _, dir := range dirList {
			newDir := fmt.Sprintf("exports/%s/%s", audit.Name, dir)
			if _, err := os.Stat(newDir); os.IsNotExist(err) {
				if err := os.MkdirAll(newDir, os.ModePerm); err != nil {
					log.Fatal(err)
				}
			}
		}

		fmt.Printf("[+] Exporting Audit:(%s) Company:(%s)", audit.Name, audit.Company.Name)
		err = ExportAudit(audit)
		if err != nil {
			log.Fatal("[-] Error exporting audit response body (exporting audit): ", err)
		}
		fmt.Println("\n[+] Done exporting exporting audit info...")

		////////////////////////////////////////
		// THIS IS WHERE WE EXPORT THE REPORT //
		////////////////////////////////////////

		fmt.Println("\n[+] Exporting Engagement Report...")

		err = ExportReport(audit.ID, audit.Name)
		if err != nil {
			log.Fatal("[-] Error reading response body (exporting report): ", err)
		}
		fmt.Println("[+] Finished Exporting Engagement Report")

		fmt.Println("[+] Finished Getting Requested Audit Information!")

	}

	////////////////////////////////////////////////
	// THIS IS WHERE WE EXPORT VULNERABILITIES DB //
	////////////////////////////////////////////////

	fmt.Println("\n[+] Dumping APIVulnerabilities Database...")
	err = ExportVulnerabilitiesDatabase("exports/VULN-DB.json")
	if err != nil {
		log.Fatal("[-] Error exporting vulnerabilities database: ", err)
	}
	fmt.Println("[+] Finished Dumping APIVulnerabilities Database!")

	///////////////////////////////////
	// THIS IS WHERE WE DUMP MONGODB //
	///////////////////////////////////

	if pwndocSSHUser != "" || pwndocSSHHost != "" {
		fmt.Println("\n[+] Dumping MongoDB...")
		err = ExportMongoDB("exports/mongodb.dump", pwndocSSHUser, pwndocSSHHost)
		if err != nil {
			log.Printf("[-] Error exporting mongodb: %s", err)
			return
		}
		fmt.Println("[+] Finished Dumping MongoDB!")
	}

	//////////////////////////////////////
	// THIS IS WHERE WE EXPORT SETTINGS //
	//////////////////////////////////////

	fmt.Println("\n[+] Dumping APISettings...")
	err = ExportSettings("exports/settings.json")
	if err != nil {
		log.Fatal("[-] Error exporting settings: ", err)
	}
	fmt.Println("[+] Finished Dumping APISettings!")

}

func ExportAudit(audit pwndoc.APIAudit) error {
	retrievedAuditInformation, err := pwndocAPI.GetAudit(audit.ID)
	if err != nil {
		return err
	}

	file, _ := json.MarshalIndent(retrievedAuditInformation, "", "  ")
	fileName := fmt.Sprintf("exports/%s/audit-findings/OG-%s-finding.json", audit.Name, retrievedAuditInformation.Data.ID)
	err = os.WriteFile(fileName, file, 0644)
	if err != nil {
		return err
	}

	for _, finding := range retrievedAuditInformation.Data.Findings {
		file, err := json.MarshalIndent(finding, "", "  ")
		if err != nil {
			return err
		}
		fileName := fmt.Sprintf("exports/%s/audit-findings/%s-finding.json", audit.Name, finding.ID)
		err = os.WriteFile(fileName, file, 0644)
		if err != nil {
			return err
		}

		err = pwndoc.DownloadImagesInContent(finding.Description, pwndocAPI.Token, pwndocAPI.HTTPClient, audit.Name)
		if err != nil {
			return err
		}
		err = pwndoc.DownloadImagesInContent(finding.Observation, pwndocAPI.Token, pwndocAPI.HTTPClient, audit.Name)
		if err != nil {
			return err
		}
		err = pwndoc.DownloadImagesInContent(finding.Poc, pwndocAPI.Token, pwndocAPI.HTTPClient, audit.Name)
		if err != nil {
			return err
		}
		err = pwndoc.DownloadImagesInContent(finding.AffectedAssets, pwndocAPI.Token, pwndocAPI.HTTPClient, audit.Name)
		if err != nil {
			return err
		}
		err = pwndoc.DownloadImagesInContent(finding.Remediation, pwndocAPI.Token, pwndocAPI.HTTPClient, audit.Name)
		if err != nil {
			return err
		}
	}

	return nil
}

func ExportReport(auditID, auditName string) error {
	reportURL := fmt.Sprintf("%s/api/audits/%s/generate", pwndocAPI.URL, auditID)
	body, err := pwndoc.BodyFromGetRequest(reportURL, pwndocAPI.Token, pwndocAPI.HTTPClient)
	if err != nil {
		return err
	}
	reportFileName := fmt.Sprintf("exports/%s/report/%s.docx", auditName, auditName)
	return os.WriteFile(reportFileName, body, 0644)
}

func ExportVulnerabilitiesDatabase(exportFile string) error {
	exportedVulnerabilities, err := pwndocAPI.ExportVulnerabilities()
	if err != nil {
		return err
	}

	file, err := json.MarshalIndent(exportedVulnerabilities.Data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(exportFile, file, 0644)
}

func ExportMongoDB(exportFile string, pwndocSSHUser string, pwndocSSHHost string) error {
	if //goland:noinspection ALL
	runtime.GOOS == "windows" {
		return errors.New("not supported on windows yet")
	}

	baseCmd := "ssh"

	cmdArgs := []string{
		fmt.Sprintf("%s@%s", pwndocSSHUser, pwndocSSHHost),
		MongoDBDockerExport,
	}

	if pwndocSSHHost == "" {
		// no IP assume local
		baseCmd = "bash"
		cmdArgs = []string{
			"-c",
			MongoDBDockerExport,
		}
	}

	out, err := exec.Command(baseCmd, cmdArgs...).Output()
	if err != nil {
		fmt.Println(out)
		return err
	}
	return os.WriteFile(exportFile, out, 0644)
}

func ExportSettings(exportFile string) error {
	exportedSettings, err := GetPwndocAPI().GetSettings()
	if err != nil {
		return err
	}

	bytesForFile, err := json.MarshalIndent(exportedSettings, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(exportFile, bytesForFile, 0644)
}
