package pwndoctor

import (
	"fmt"
	"log"

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

	// include the audits to clone, should probably check and make sure it's only one before this happens.
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

		fmt.Println("[+] Audit ID to clone: ", audit.ID)
		fmt.Println("[+] Cloning audit: ", audit.Name, " to ", destination)

		err = CloneAudit(audit, destination)
		if err != nil {
			log.Fatal("[-] Error cloning audit response body (cloning audit): ", err)
		}
		fmt.Println("\n[+] Done cloning exporting audit info...")

	}

}

func CloneAudit(audit pwndoc.APIAudit, destination string) error {

	retrievedAuditInformation, err := pwndocAPI.GetAudit(audit.ID)
	if err != nil {
		return err
	}

	//get the language and audit type from the cloned audit
	lang := retrievedAuditInformation.Data.Language
	auditType := retrievedAuditInformation.Data.AuditType

	//create the audit
	createdaudit, err := pwndocAPI.CreateAudit(destination, lang, auditType)
	if err != nil {
		return err
	}
	createdauditid := createdaudit.Datas.Audit.ID

	println("[+] Created audit ID = " + createdaudit.Datas.Audit.ID)

	// Create the custom sections YOLO
	for a, section := range retrievedAuditInformation.Data.Sections {
		fmt.Println("Creating section = ", section.Name)
		err = pwndocAPI.CreateNewSection(createdauditid, section, createdaudit.Datas.Audit.Sections[a].ID)
		if err != nil {
			return err
		}
	}
	// Create the findings YOLO
	for _, finding := range retrievedAuditInformation.Data.Findings {
		fmt.Println("Creating section = ", finding.Title)
		err = pwndocAPI.CreateNewFinding(createdauditid, finding)
		if err != nil {
			return err
		}

		// For the images, the reference to the image is all that's copied over. I tested deleting an image from the original audit and it was still present in the cloned audit
		// At the moment, pwndoc doesnt seem to send a DELETE request to the image when deleting the image within the audit.
		// this should probably clone the image itself so it's not referencing the same image in both audits but im fine with how it is for now.
	}

	return nil
}
