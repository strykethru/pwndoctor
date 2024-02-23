package pwndoc

import "time"

type APIAudit struct {
	ID            string `json:"_id"`
	Name          string `json:"name"`
	AuditType     string `json:"auditType"`
	Collaborators []struct {
		ID       string `json:"_id"`
		Username string `json:"username"`
	} `json:"collaborators"`
	Reviewers []struct {
		ID       string `json:"_id"`
		Username string `json:"username"`
	} `json:"reviewers"`
	Language string `json:"language"`
	Template struct {
		ID        string    `json:"_id"`
		Name      string    `json:"name"`
		Ext       string    `json:"ext"`
		CreatedAt time.Time `json:"createdAt"`
		UpdatedAt time.Time `json:"updatedAt"`
		V         int       `json:"__v"`
	} `json:"template"`
	Creator struct {
		ID        string `json:"_id"`
		Username  string `json:"username"`
		Firstname string `json:"firstname"`
		Lastname  string `json:"lastname"`
		Role      string `json:"role"`
	} `json:"creator"`
	Sections []struct {
		Field        string `json:"field"`
		Name         string `json:"name"`
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
				Options     []any  `json:"options"`
			} `json:"customField"`
			Text any `json:"text"`
		} `json:"customFields"`
		ID string `json:"_id"`
	} `json:"sections"`
	CustomFields []any `json:"customFields"`
	SortFindings []struct {
		Category  string `json:"category"`
		SortValue string `json:"sortValue"`
		SortOrder string `json:"sortOrder"`
		SortAuto  bool   `json:"sortAuto"`
	} `json:"sortFindings"`
	State     string              `json:"state"`
	Approvals []any               `json:"approvals"`
	Scope     []any               `json:"scope"`
	Findings  []APIFindingDetails `json:"findings"`
	CreatedAt time.Time           `json:"createdAt"`
	UpdatedAt time.Time           `json:"updatedAt"`
	V         int                 `json:"__v"`

	Company struct {
		ID   string `json:"_id"`
		Name string `json:"name"`
	} `json:"company"`
}

type APIResponseAudits struct {
	Status string     `json:"status"`
	Data   []APIAudit `json:"datas"`
}

type APIResponseAudit struct {
	Status string   `json:"status"`
	Data   APIAudit `json:"datas"`
}
