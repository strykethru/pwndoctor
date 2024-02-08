package pwndoc

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/fatih/color"
	"io"
	"net/http"
	"net/url"
	"os"
)

var URL string

func UseURL(pwndocURL string) {
	URL = pwndocURL
}

func CreateHttpClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	proxyEnv := os.Getenv("HTTP_PROXY")
	if proxyEnv != "" {
		proxyURL, _ := url.Parse(proxyEnv)
		proxy := http.ProxyURL(proxyURL)
		transport.Proxy = proxy
	}

	var client = &http.Client{
		Transport: transport,
	}
	return client
}

func GetCookie(username string, password string, totp string) string {
	red := color.New(color.FgRed).PrintfFunc()

	cfg := &tls.Config{
		InsecureSkipVerify: true,
	}
	http.DefaultClient.Transport = &http.Transport{
		TLSClientConfig: cfg,
	}

	var token APIResponseLogin
	fullToken := ""
	credentials := fmt.Sprintf("{\"username\": \"%s\", \"password\": \"%s\", \"totpToken\": \"%s\"}", username, password, totp)
	tokenURL := fmt.Sprintf("%s/api/users/token", URL)
	resp, err := http.Post(tokenURL, "application/json", bytes.NewBuffer([]byte(credentials)))
	if err != nil {
		red("\n[-] Error submitting APILogin: %s\n", err)
		os.Exit(0)
	}

	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&token)
	if token.Data.Token == "" || err != nil {
		red("[-] Error decoding received token: %s\n", err)
		os.Exit(0)
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	fullToken = fmt.Sprintf("token=JWT%%20%s", token.Data.Token)
	return fullToken
}

func MakePostRequest(url string, bodyReader *bytes.Reader, token string, client *http.Client) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func MakePutRequest(url string, bodyReader *bytes.Reader, token string, client *http.Client) (*http.Response, error) {
	req, err := http.NewRequest("PUT", url, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func MakeGetRequest(url string, token string, client *http.Client) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, err
}

func BodyFromGetRequest(url string, token string, client *http.Client) ([]byte, error) {
	resp, err := MakeGetRequest(url, token, client)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func BodyFromPostRequest(url string, bodyReader *bytes.Reader, token string, client *http.Client) ([]byte, error) {
	resp, err := MakePostRequest(url, bodyReader, token, client)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func BodyFromPutRequest(url string, bodyReader *bytes.Reader, token string, client *http.Client) ([]byte, error) {
	resp, err := MakePutRequest(url, bodyReader, token, client)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}
