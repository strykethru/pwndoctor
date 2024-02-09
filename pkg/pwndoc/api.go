package pwndoc

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"

	"github.com/strykethru/pwndoctor/pkg/util"
)

type API struct {
	URL        string
	HTTPClient *http.Client
	Token      string
}

const PathAudits = "/api/audits"
const PathDataAuditTypes = "/api/data/audit-types"
const PathDataCustomFields = "/api/data/custom-fields"
const PathDataLanguages = "/api/data/languages"
const PathDataSections = "/api/data/sections"
const PathDataVulnerabilityCategories = "/api/data/vulnerability-categories"
const PathDataVulnerabilityTypes = "/api/data/vulnerability-types"
const PathSettings = "/api/settings"
const PathTemplates = "/api/templates"
const PathUserInit = "/api/users/init"
const PathUsers = "/api/users"
const PathVulnerabilities = "/api/vulnerabilities"
const PathVulnerabilitiesExport = "/api/vulnerabilities/export"

func New(pwndocURL string) *API {
	return &API{
		URL:        pwndocURL,
		HTTPClient: CreateHttpClient(),
		Token:      "",
	}
}

func (api *API) Auth(username, password, totp string) string {
	api.Token = GetCookie(username, password, totp)
	return api.Token
}

func (api *API) Post(path string, postBody *bytes.Reader) (*http.Response, error) {
	requestURL := fmt.Sprintf("%s%s", api.URL, path)
	return MakePostRequest(requestURL, postBody, api.Token, api.HTTPClient)
}

func (api *API) Get(path string) (*http.Response, error) {
	requestURL := fmt.Sprintf("%s%s", api.URL, path)
	return MakeGetRequest(requestURL, api.Token, api.HTTPClient)
}

func (api *API) Put(path string, postBody *bytes.Reader) (*http.Response, error) {
	requestURL := fmt.Sprintf("%s%s", api.URL, path)
	return MakePutRequest(requestURL, postBody, api.Token, api.HTTPClient)
}

func (api *API) PostResponseBody(path string, postBody *bytes.Reader) ([]byte, error) {
	requestURL := fmt.Sprintf("%s%s", api.URL, path)
	return BodyFromPostRequest(requestURL, postBody, api.Token, api.HTTPClient)
}

func (api *API) GetResponseBody(path string) ([]byte, error) {
	requestURL := fmt.Sprintf("%s%s", api.URL, path)
	return BodyFromGetRequest(requestURL, api.Token, api.HTTPClient)
}

func (api *API) PutResponseBody(path string, postBody *bytes.Reader) ([]byte, error) {
	requestURL := fmt.Sprintf("%s%s", api.URL, path)
	return BodyFromPutRequest(requestURL, postBody, api.Token, api.HTTPClient)
}

// CreateInitialUser Create initial user on uninitialized pwndoc instance. will error if already initialized
func (api *API) CreateInitialUser(customInitialUser APIInitialUser) (*APIResponseLogin, error) {
	bodyReader, err := util.MarshalStuff(customInitialUser)
	if err != nil {
		return nil, err
	}

	initialUserCreateResponseBody, err := api.PostResponseBody(PathUserInit, bodyReader)
	if err != nil {
		return nil, err
	}

	var initialUserResponse APIResponseLogin
	err = json.Unmarshal(initialUserCreateResponseBody, &initialUserResponse)
	return &initialUserResponse, err
}

func (api *API) CreateLanguage(customLanguage APILanguage) (bool, error) {
	bodyReader, err := util.MarshalStuff(customLanguage)
	if err != nil {
		return false, err
	}

	_, err = api.Post(PathDataLanguages, bodyReader)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (api *API) GetCustomFields() (*APIResponseCustomFields, error) {
	customFieldsResponseBody, err := api.GetResponseBody(PathDataCustomFields)
	if err != nil {
		return nil, err
	}

	var retrievedCustomFields APIResponseCustomFields
	err = json.Unmarshal(customFieldsResponseBody, &retrievedCustomFields)
	return &retrievedCustomFields, err

}

func (api *API) GetAudits() (*APIResponseAudits, error) {
	auditsResponseBody, err := api.GetResponseBody(PathAudits)
	if err != nil {
		return nil, err
	}

	var retrievedAudits APIResponseAudits
	err = json.Unmarshal(auditsResponseBody, &retrievedAudits)
	return &retrievedAudits, err
}

func (api *API) GetAudit(auditID string) (*APIResponseAudit, error) {
	auditResponseBody, err := api.GetResponseBody(path.Join(PathAudits, auditID))
	if err != nil {
		return nil, err
	}

	var retrievedAuditInformation APIResponseAudit
	err = json.Unmarshal(auditResponseBody, &retrievedAuditInformation)
	return &retrievedAuditInformation, err
}

func (api *API) CreateReportTemplate(docName, docExt string, templateFile *os.File) (bool, error) {

	// Read entire docx into byte slice
	reader := bufio.NewReader(templateFile)
	content, _ := io.ReadAll(reader)

	// Encode as base64
	encodedTemplate := base64.StdEncoding.EncodeToString(content)

	customTemplate := APITemplate{
		Name: docName,
		Ext:  docExt,
		File: encodedTemplate,
	}

	bodyReader, err := util.MarshalStuff(customTemplate)
	if err != nil {
		return false, err
	}

	_, err = api.Post(PathTemplates, bodyReader)
	return err != nil, err
}

func (api *API) GetReportTemplates() (*APIResponseTemplates, error) {

	auditsResponseBody, err := api.GetResponseBody(PathTemplates)
	if err != nil {
		return nil, err
	}

	var retrievedTemplates APIResponseTemplates
	err = json.Unmarshal(auditsResponseBody, &retrievedTemplates)
	return &retrievedTemplates, err
}

func (api *API) CreateAuditTypes(auditType APIAuditType) (bool, error) {
	//Marshal data back to JSON
	bodyReader, err := util.MarshalStuff(auditType)
	if err != nil {
		log.Fatalf("Error unmarshalling data: %s", err)
	}

	_, err = api.PostResponseBody(PathDataAuditTypes, bodyReader)
	return err != nil, err
}

func (api *API) CreateVulnerabilityType(vulnerabilityType APIVulnerabilityType) (bool, error) {
	//Marshal data back to JSON
	bodyReader, err := util.MarshalStuff(vulnerabilityType)
	if err != nil {
		log.Fatalf("Error unmarshalling data: %s", err)
	}

	_, err = api.Post(PathDataVulnerabilityTypes, bodyReader)
	return err != nil, err
}

func (api *API) CreateVulnerabilityCategory(vulnerabilityCategory APIVulnerabilityCategory) (bool, error) {
	//Marshal data back to JSON
	bodyReader, err := util.MarshalStuff(vulnerabilityCategory)
	if err != nil {
		log.Fatalf("Error unmarshalling data: %s", err)
	}

	_, err = api.Post(PathDataVulnerabilityCategories, bodyReader)
	return err != nil, err
}

func (api *API) CreateSection(customSection APISection) (bool, error) {
	//Marshal data back to JSON
	bodyReader, err := util.MarshalStuff(customSection)
	if err != nil {
		log.Fatalf("Error unmarshalling data: %s", err)
	}

	_, err = api.Post(PathDataSections, bodyReader)
	return err != nil, err
}

func (api *API) CreateCustomField(customField APICustomField) (bool, error) {
	//Marshal data back to JSON
	bodyReader, err := util.MarshalStuff(customField)
	if err != nil {
		log.Fatalf("Error unmarshalling data: %s", err)
	}

	_, err = api.Post(PathDataCustomFields, bodyReader)
	return err != nil, err
}

func (api *API) CreateVulnerabilities(vulnerabilities APIVulnerabilities) (bool, error) {
	bodyReader, err := util.MarshalStuff(vulnerabilities)
	if err != nil {
		return false, err
	}

	body, err := api.PostResponseBody(PathVulnerabilities, bodyReader)
	fmt.Println(string(body))
	if err != nil {
		return false, err
	}

	return true, nil
}

func (api *API) ExportVulnerabilities() (*APIResponseVulnerabilitiesExport, error) {
	body, err := api.GetResponseBody(PathVulnerabilitiesExport)
	if err != nil {
		return nil, err
	}

	var exportedVulnerabilities APIResponseVulnerabilitiesExport
	err = json.Unmarshal(body, &exportedVulnerabilities)
	return &exportedVulnerabilities, err
}

func (api *API) CreateUsers(customUsers []APIUser) (bool, error) {
	bodyReader, err := util.MarshalStuff(customUsers)
	if err != nil {
		return false, err
	}

	_, err = api.Post(PathUsers, bodyReader)
	if err != nil {
		return false, err
	}

	return true, nil
}

func (api *API) CreateSettings(customSettings APISettings) (bool, error) {
	bodyReader, err := util.MarshalStuff(customSettings)
	if err != nil {
		return false, err
	}

	body, err := api.PutResponseBody(PathSettings, bodyReader)
	fmt.Println(string(body))
	if err != nil {
		return false, err
	}

	return true, nil
}

func (api *API) GetSettings() (*APIResponseSettings, error) {
	body, err := api.GetResponseBody(PathSettings)
	if err != nil {
		return nil, err
	}

	var exportedSettings APIResponseSettings
	err = json.Unmarshal(body, &exportedSettings)
	return &exportedSettings, err
}
