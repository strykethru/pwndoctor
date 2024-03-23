package pwndoctor

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/strykethru/pwndoctor/pkg/pwndoc"
)

func DoClone(includeAuditNames []string, destination string) {

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
				fmt.Println("Skipping..." + audit.Name)
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
		err = CloneAudit(audit, destination)
		if err != nil {
			log.Fatal("[-] Error exporting audit response body (exporting audit): ", err)
		}
		fmt.Println("\n[+] Done exporting exporting audit info...")

		// Import the Audit
		//err = PostCloneAudit(audit)

	}

}

func CloneAudit(audit pwndoc.APIAudit, destination string) error {

	{
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

		println("\n importing audit")
		lang := retrievedAuditInformation.Data.Language
		println("lang =" + lang)
		auditType := retrievedAuditInformation.Data.AuditType
		println("auditType =" + auditType)

		err = pwndocAPI.CreateAudit(destination, lang, auditType)
		if err != nil {
			return err
		}

		return nil

	}
}

// func PostCloneAudit(audit pwndoc.APIAudit) error {

// 	{
// 		retrievedAuditInformation, err := pwndocAPI.GetAudit(audit.ID)
// 		if err != nil {
// 			return err
// 		}

// 		file, _ := json.MarshalIndent(retrievedAuditInformation, "", "  ")
// 		fileName := fmt.Sprintf("exports/%s/audit-findings/OG-%s-finding.json", audit.Name, retrievedAuditInformation.Data.ID)
// 		err = os.WriteFile(fileName, file, 0644)
// 		if err != nil {
// 			return err
// 		}

// 		for _, finding := range retrievedAuditInformation.Data.Findings {
// 			file, err := json.MarshalIndent(finding, "", "  ")
// 			if err != nil {
// 				return err
// 			}
// 			fileName := fmt.Sprintf("exports/%s/audit-findings/%s-finding.json", audit.Name, finding.ID)
// 			err = os.WriteFile(fileName, file, 0644)
// 			if err != nil {
// 				return err
// 			}

// 			err = pwndoc.DownloadImagesInContent(finding.Description, pwndocAPI.Token, pwndocAPI.HTTPClient, audit.Name)
// 			if err != nil {
// 				return err
// 			}
// 			err = pwndoc.DownloadImagesInContent(finding.Observation, pwndocAPI.Token, pwndocAPI.HTTPClient, audit.Name)
// 			if err != nil {
// 				return err
// 			}
// 			err = pwndoc.DownloadImagesInContent(finding.Poc, pwndocAPI.Token, pwndocAPI.HTTPClient, audit.Name)
// 			if err != nil {
// 				return err
// 			}
// 			err = pwndoc.DownloadImagesInContent(finding.AffectedAssets, pwndocAPI.Token, pwndocAPI.HTTPClient, audit.Name)
// 			if err != nil {
// 				return err
// 			}
// 			err = pwndoc.DownloadImagesInContent(finding.Remediation, pwndocAPI.Token, pwndocAPI.HTTPClient, audit.Name)
// 			if err != nil {
// 				return err
// 			}
// 		}

// 		return nil
// 	}
// }
