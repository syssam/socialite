package apple

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"time"

	"github.com/syssam/socialite/providers"
)

var scopeSeparator = " "

var scopes = []string{
	"name",
	"email",
}

type appleProvider struct {
	providers.Provider
}

var tokenTTL = 24 * time.Hour

func NewProvider(clientID, clientSecret, redirectURL string) appleProvider {
	return appleProvider{
		Provider: providers.Provider{
			ClientID:       clientID,
			ClientSecret:   clientSecret,
			Scopes:         scopes,
			ScopeSeparator: scopeSeparator,
			RedirectURL:    redirectURL,
		},
	}
}

func (p appleProvider) GetAuthUrl(state string) string {
	return p.Provider.BuildAuthUrlFromBase("https://appleid.apple.com/auth/authorize", state)
}

func (p appleProvider) GetTokenUrl() string {
	return "https://appleid.apple.com/auth/token"
}

func (p appleProvider) GetAccessTokenResponse(code string) (map[string]interface{}, error) {
	return p.Provider.GetAccessTokenResponse(code, p)
}

func (p appleProvider) GetTokenFields(code string) map[string]string {
	fields := p.Provider.GetTokenFields(code)
	fields["grant_type"] = "authorization_code"
	return fields
}

func (p appleProvider) GetUserByAuthorizationCode(code string) (*providers.User, error) {
	res, err := p.GetAccessTokenResponse(code)
	if err != nil {
		return nil, err
	}

	if _, ok := res["id_token"]; !ok {
		return nil, fmt.Errorf("id_token not found")
	}

	token, _, err := new(jwt.Parser).ParseUnverified(res["id_token"].(string), &IDTokenClaims{})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*IDTokenClaims); ok {
		if claims.EmailVerified != "true" {
			return nil, fmt.Errorf("email not verified")
		}
		return &providers.User{
			ID:    claims.Subject,
			Name:  claims.Name,
			Email: claims.Email,
		}, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func (p appleProvider) GetUserByToken(token string) (*providers.User, error) {
	// todo: implement
	panic("apple does not support this method")
}

type IDTokenClaims struct {
	jwt.RegisteredClaims
	Name           string `json:"name"`
	Email          string `json:"email"`
	EmailVerified  string `json:"email_verified"`
	IsPrivateEmail string `json:"is_private_email"`
}

type profile struct {
	Sub           string
	Name          string
	Email         string
	EmailVerified bool `json:"email_verified"`
}

type responseError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func CreateClientSecret(key, teamID, clientID, keyID string) (string, error) {
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("ParsePKCS8PrivateKey: %v", err)
	}

	// Create a new JWT token.
	/*
		token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
			"iss": teamID,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(tokenTTL).Unix(),
			"aud": "https://appleid.apple.com",
			"sub": clientID,
			"alg": "ES256",
			"kid": keyID,
		})
	*/

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
		Issuer:    teamID,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenTTL)),
		Audience:  []string{"https://appleid.apple.com"},
		Subject:   clientID,
	})

	token.Header["kid"] = keyID

	// Sign the token with the private key.
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("SignedString: %v", err)
	}

	return tokenString, nil
}
