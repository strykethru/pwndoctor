package pwndoc

import (
	"fmt"
)

type APILogin struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

//goland:noinspection SpellCheckingInspection
type APISettings struct {
	Report struct {
		Public struct {
			CVSSColors struct {
				NoneColor     string `json:"noneColor"`
				LowColor      string `json:"lowColor"`
				MediumColor   string `json:"mediumColor"`
				HighColor     string `json:"highColor"`
				CriticalColor string `json:"criticalColor"`
			} `json:"cvssColors"`
			RemediationColorsComplexity struct {
				LowColor    string `json:"lowColor"`
				MediumColor string `json:"mediumColor"`
				HighColor   string `json:"highColor"`
			} `json:"remediationColorsComplexity"`
			RemediationColorsPriority struct {
				LowColor    string `json:"lowColor"`
				MediumColor string `json:"mediumColor"`
				HighColor   string `json:"highColor"`
				UrgentColor string `json:"urgentColor"`
			} `json:"remediationColorsPriority"`
			Captions                      []string `json:"captions"`
			ExtendCvssTemporalEnvironment bool     `json:"extendCvssTemporalEnvironment"`
		} `json:"public"`
		Private struct {
			ImageBorder      bool   `json:"imageBorder"`
			ImageBorderColor string `json:"imageBorderColor"`
		} `json:"private"`
		Enabled bool `json:"enabled"`
	} `json:"report"`
	Reviews struct {
		Public struct {
			MandatoryReview bool `json:"mandatoryReview"`
			MinReviewers    int  `json:"minReviewers"`
		} `json:"public"`
		Private struct {
			RemoveApprovalsUponUpdate bool `json:"removeApprovalsUponUpdate"`
		} `json:"private"`
		Enabled bool `json:"enabled"`
	} `json:"reviews"`
}

type APIInitialUser struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	Firstname string `json:"firstname"`
	Lastname  string `json:"lastname"`
}

type APIImage struct {
	ID      string `json:"_id,omitempty"`
	Value   string `json:"value"`
	Name    string `json:"name"`
	AuditID any    `json:"auditId"`
}

type APIResponseImage struct {
	Status string   `json:"status"`
	Data   APIImage `json:"datas"`
}

type APILanguage struct {
	Locale   string `json:"locale"`
	Language string `json:"language"`
}

type APISection struct {
	Name  string `json:"name"`
	Field string `json:"field"`
	Icon  string `json:"icon"`
}

type APICustomField struct {
	ID          string `json:"_id"`
	FieldType   string `json:"fieldType"`
	Label       string `json:"label"`
	Display     string `json:"display"`
	DisplaySub  string `json:"displaySub"`
	Size        int    `json:"size"`
	Offset      int    `json:"offset"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
	Text        []struct {
		Locale string `json:"locale"`
		Value  string `json:"value"`
	} `json:"text"`
	Options  []interface{} `json:"options"`
	Position int           `json:"position"`
}

type APIVulnerabilityCategory struct {
	Name      string `json:"name"`
	SortValue string `json:"sortValue"`
	SortOrder string `json:"sortOrder"`
	SortAuto  bool   `json:"sortAuto"`
}

type APIVulnerabilityType struct {
	Name   string `json:"name"`
	Locale string `json:"locale"`
}

type APIAuditType struct {
	Name      string `json:"name"`
	Templates []struct {
		Name     string `json:"name"`
		Locale   string `json:"locale"`
		Template string `json:"template"`
	} `json:"templates"`
	Sections []string      `json:"sections"`
	Hidden   []interface{} `json:"hidden"`
}

type APITemplate struct {
	ID   string `json:"_id,omitempty"`
	Name string `json:"name,omitempty"`
	File string `json:"file,omitempty"`
	Ext  string `json:"ext,omitempty"`
}

type APIUser struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	Firstname   string `json:"firstname"`
	Lastname    string `json:"lastname"`
	Role        string `json:"role"`
	TotpEnabled bool   `json:"totpEnabled"`
	Enabled     bool   `json:"enabled"`
	Email       string `json:"email"`
	Phone       string `json:"phone"`
}

type APIResponseTemplates struct {
	Status string        `json:"status"`
	Data   []APITemplate `json:"datas"`
}

type APIResponseCustomFields struct {
	Status string           `json:"status"`
	Data   []APICustomField `json:"datas"`
}

func (rcd *APIResponseCustomFields) GetVulnerabilityCustomDataID(vulnerabilityType, customDataLabel string) string {
	for i := 0; i < len(rcd.Data); i++ {
		if rcd.Data[i].Display == "vulnerability" && rcd.Data[i].Label == customDataLabel && rcd.Data[i].DisplaySub == vulnerabilityType {
			return rcd.Data[i].ID
		}
	}
	panic(fmt.Sprintf("failed to find custom data field %s on vulnerability type %s", customDataLabel, vulnerabilityType))
}

type APIVulnerabilities []struct {
	CVSSv3                string `json:"cvssv3"`
	Priority              string `json:"priority"`
	RemediationComplexity string `json:"remediationComplexity"`
	Details               []struct {
		Locale       string   `json:"locale"`
		Title        string   `json:"title"`
		VulnType     string   `json:"vulnType"`
		Description  string   `json:"description"`
		Observation  string   `json:"observation"`
		Remediation  string   `json:"remediation"`
		References   []string `json:"references"`
		CustomFields []struct {
			CustomField struct {
				ID          string `json:"_id"`
				FieldType   string `json:"fieldType"`
				Label       string `json:"label"`
				Display     string `json:"display"`
				DisplaySub  string `json:"displaySub"`
				Size        int    `json:"size"`
				Offset      int    `json:"offset"`
				Required    bool   `json:"required"`
				Description string `json:"description"`
				Options     []struct {
					Locale string `json:"locale"`
					Value  string `json:"value"`
				} `json:"options"`
			} `json:"customField"`
			Text string `json:"text"`
		} `json:"customFields"`
	} `json:"details"`
	Category string `json:"category"`
}

type APIResponseLogin struct {
	Status string `json:"status"`
	Data   struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refreshToken"`
	} `json:"datas"`
}

type APIFindingDetails struct {
	Identifier            int      `json:"identifier,omitempty"`
	Title                 string   `json:"title,omitempty"`
	VulnType              string   `json:"vulnType,omitempty"`
	Description           string   `json:"description,omitempty"`
	Observation           string   `json:"observation,omitempty"`
	Remediation           string   `json:"remediation,omitempty"`
	RemediationComplexity int      `json:"remediationComplexity,omitempty"`
	Priority              int      `json:"priority,omitempty"`
	References            []string `json:"references,omitempty"`
	CVSSv3                string   `json:"cvssv3,omitempty"`
	Status                int      `json:"status,omitempty"`
	Category              string   `json:"category,omitempty"`
	CustomFields          []struct {
		CustomField struct {
			ID          string `json:"_id,omitempty"`
			FieldType   string `json:"fieldType,omitempty"`
			Label       string `json:"label,omitempty"`
			Display     string `json:"display,omitempty"`
			DisplaySub  string `json:"displaySub,omitempty"`
			Size        int    `json:"size,omitempty"`
			Offset      int    `json:"offset,omitempty"`
			Required    bool   `json:"required,omitempty"`
			Description string `json:"description,omitempty"`
			Options     []struct {
				Locale string `json:"locale,omitempty"`
				Value  string `json:"value,omitempty"`
			} `json:"options,omitempty"`
		} `json:"customField,omitempty"`
		Text string `json:"text,omitempty"`
	} `json:"customFields,omitempty"`
	ID         string `json:"_id,omitempty"`
	Paragraphs []any  `json:"paragraphs,omitempty"`
	Poc        string `json:"poc,omitempty"`
	Scope      string `json:"scope,omitempty"`

	Type               string  `json:"type,omitempty"`
	MitreAttack        string  `json:"mitre_attack,omitempty"`
	Count              int     `json:"count,omitempty"`
	Closed             bool    `json:"closed,omitempty"`
	CVSSScore          float64 `json:"cvss_score,omitempty"`
	CVSSString         string  `json:"cvss_string,omitempty"`
	AffectedAssets     string  `json:"affected_assets,omitempty"`
	Evidence           string  `json:"evidence,omitempty"`
	Detection          string  `json:"detection,omitempty"`
	Summary            string  `json:"summary,omitempty"`
	Recommendations    string  `json:"recommendations,omitempty"`
	Reviewed           bool    `json:"reviewed,omitempty"`
	ResourceIdentifier string  `json:"resource_identifier,omitempty"`
	CreatedDate        string  `json:"created_date,omitempty"`
	UpdatedDate        string  `json:"updated_date,omitempty"`
	ExternalUUID       string  `json:"external_uuid,omitempty"`

	// maybe remove this
	Criticality   string `json:"criticality,omitempty"`
	AttackSurface string `json:"attack_surface,omitempty"`
}

type APIResponseVulnerabilitiesExport struct {
	Status string `json:"status"`
	Data   []struct {
		CVSSv3                string `json:"cvssv3"`
		Priority              int    `json:"priority"`
		RemediationComplexity int    `json:"remediationComplexity"`
		Details               []struct {
			Locale       string   `json:"locale"`
			Title        string   `json:"title"`
			VulnType     string   `json:"vulnType"`
			Description  string   `json:"description"`
			Observation  string   `json:"observation"`
			Remediation  string   `json:"remediation"`
			References   []string `json:"references"`
			CustomFields []struct {
				CustomField string `json:"customField"`
				Text        string `json:"text"`
			} `json:"customFields"`
		} `json:"details"`
		Category string `json:"category"`
	} `json:"datas"`
}

type APIResponseSettings struct {
	Status string      `json:"status"`
	Data   APISettings `json:"datas"`
}
