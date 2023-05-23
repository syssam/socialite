package facebook

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/syssam/socialite/providers"
)

type facebookProvider struct {
	providers.Provider
	graphURL string
	version  string
	fields   []string
}

var scopes = []string{
	"email",
}

func NewProvider(clientID, clientSecret, redirectURL string) facebookProvider {
	return facebookProvider{
		Provider: providers.Provider{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Scopes:       scopes,
			RedirectURL:  redirectURL,
		},
		graphURL: "https://graph.facebook.com",
		version:  "v3.3",
		fields:   []string{"name", "email", "gender", "verified", "link"},
	}
}

func (p facebookProvider) GetAuthUrl(state string) string {
	return p.Provider.BuildAuthUrlFromBase("https://www.facebook.com/"+p.version+"/dialog/oauth", state)
}

func (p facebookProvider) GetTokenUrl() string {
	return p.graphURL + "/" + p.version + "/oauth/access_token"
}

func (p facebookProvider) GetAccessTokenResponse(code string) (map[string]interface{}, error) {
	return p.Provider.GetAccessTokenResponse(code, p)
}

func (p facebookProvider) GetUserByToken(token string) (*providers.User, error) {
	req, err := http.NewRequest("GET", p.graphURL+"/"+p.version+"/me", nil)
	if err != nil {
		return nil, fmt.Errorf("http.NewRequest(): %v", err)
	}

	query := req.URL.Query()
	query.Add("access_token", token)
	query.Add("fields", strings.Join(p.fields, ","))
	req.URL.RawQuery = query.Encode()

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+token)

	resp, err := p.Client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	jsonMap := map[string]string{}
	err = json.NewDecoder(resp.Body).Decode(&jsonMap)
	if err != nil {
		return nil, err
	}

	return &providers.User{
		ID:             jsonMap["id"],
		NickName:       jsonMap["nickname"],
		Name:           jsonMap["name"],
		Email:          jsonMap["email"],
		Avatar:         jsonMap["picture"] + "?type=normal",
		AvatarOriginal: jsonMap["picture"] + "?width=1920",
		ProfileUrl:     jsonMap["link"],
	}, nil
}
