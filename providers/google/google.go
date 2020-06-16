package google

import (
	"encoding/json"
	"github.com/syssam/socialite/providers"
	"net/http"
)

var scopeSeparator = " ";

var scopes = []string{
	"openid",
	"profile",
	"email",
};

type googleProvider struct {
	providers.Provider
}

func NewProvider(clientID, clientSecret, redirectURL string) googleProvider {
	return googleProvider{
		Provider: providers.Provider{
			ClientID:       clientID,
			ClientSecret:   clientSecret,
			Scopes:         scopes,
			ScopeSeparator: scopeSeparator,
			RedirectURL:    redirectURL,
		},
	}
}

func (p googleProvider) GetAuthUrl(state string) string {
	return p.Provider.BuildAuthUrlFromBase("https://accounts.google.com/o/oauth2/auth", state)
}

func (p googleProvider) GetTokenUrl() string {
	return "https://www.googleapis.com/oauth2/v4/token";
}

func (p googleProvider) GetAccessTokenResponse(code string) (map[string]string, error) {
	return p.Provider.GetAccessTokenResponse(code, p)
}

func (p googleProvider) GetTokenFields(code string) map[string]string {
	fields := p.Provider.GetTokenFields(code)
	fields["grant_type"] = "authorization_code"
	return fields
}

func (p googleProvider) GetUserByToken(token string) (*providers.User, error) {
	req, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v3/userinfo", nil)
	if(err != nil) {
		return nil, err
	}

    query := req.URL.Query()
    query.Add("prettyPrint", "false")
    req.URL.RawQuery = query.Encode()

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer " + token)

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
		ID:             jsonMap["sub"],
		NickName:       jsonMap["nickname"],
		Name:           jsonMap["name"],
		Email:          jsonMap["email"],
		Avatar:         jsonMap["picture"],
		AvatarOriginal: jsonMap["picture"],
	}, nil
}