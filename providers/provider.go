package providers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type Provider struct {
	Client         http.Client
	ClientID       string
	ClientSecret   string
	Parameters     []string
	Scopes         []string
	ScopeSeparator string
	RedirectURL    string
}

func (p Provider) BuildAuthUrlFromBase(authURL, state string) string {
	v := url.Values{}
	fields := p.GetCodeFields(state)
	for key, value := range fields {
		v.Set(key, value)
	}
	return authURL + "?" + v.Encode()
}

func (p Provider) GetCodeFields(state string) map[string]string {
	fields := map[string]string{
		"client_id":     p.ClientID,
		"redirect_uri":  p.RedirectURL,
		"scope":         strings.Join(p.Scopes, p.ScopeSeparator),
		"response_type": "code",
	}

	if state != "" {
		fields["state"] = state
	}

	return fields
}

func (p Provider) User() string {
	return ""
}

func (p Provider) UserFromToken() string {
	return ""
}

func (p Provider) GetAccessTokenResponse(code string, provider providerInterface) (map[string]interface{}, error) {
	data := url.Values{}
	fields := provider.GetTokenFields(code)
	for k, v := range fields {
		data.Add(k, v)
	}
	body := strings.NewReader(data.Encode())

	req, err := http.NewRequest("POST", provider.GetTokenUrl(), body)
	if err != nil {
		return nil, fmt.Errorf("http.NewRequest(): %v", err)
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	/*
		content, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
	*/

	jsonMap := make(map[string]interface{})
	err = json.NewDecoder(resp.Body).Decode(&jsonMap)
	if err != nil {
		return nil, err
	}

	if val, ok := jsonMap["error_description"]; ok {
		return nil, fmt.Errorf(val.(string))
	}

	if val, ok := jsonMap["error"]; ok {
		return nil, fmt.Errorf(val.(string))
	}

	return jsonMap, nil
}

func (p Provider) GetTokenFields(code string) map[string]string {
	return map[string]string{
		"client_id":     p.ClientID,
		"client_secret": p.ClientSecret,
		"code":          code,
		"redirect_uri":  p.RedirectURL,
	}
}

func (p Provider) setScopes(scopes []string) {
	p.Scopes = scopes
}

type providerInterface interface {
	GetAuthUrl(string) string
	GetTokenUrl() string
	GetUserByToken(string) (*User, error)
	GetTokenFields(string) map[string]string
}
