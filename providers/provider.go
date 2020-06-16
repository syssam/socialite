package providers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

type Provider struct {
	Client http.Client
	ClientID string
	ClientSecret string
	Parameters []string
	Scopes []string
	ScopeSeparator string
	RedirectURL string
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
	fields := map[string]string {
		"client_id": p.ClientID,
		"redirect_uri": p.RedirectURL,
		"scope": strings.Join(p.Scopes, p.ScopeSeparator),
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

func (p Provider) GetAccessTokenResponse(code string, provider providerInterface) (map[string]string, error) {
 	data := url.Values{}
	fields := provider.GetTokenFields(code)
	for k, v := range fields {
		data.Add(k, v)
	}
	body := strings.NewReader(data.Encode())

	fmt.Println(body)

	req, err := http.NewRequest("POST", provider.GetTokenUrl(), body)
	if(err != nil) {
		return nil, err
	}

	req.Header.Add("Accept", "application/json")
    resp, err := p.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
    content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

    jsonMap := map[string]string{}
	err = json.NewDecoder(resp.Body).Decode(&jsonMap)
    if err != nil {
    	fmt.Println(string(content))
		return nil, err
    }

	return jsonMap, nil
}

func (p Provider) GetTokenFields(code string) map[string]string {
	return map[string]string {
		"client_id": p.ClientID,
		"client_secret": p.ClientSecret,
		"code": code,
		"redirect_uri": p.RedirectURL,
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