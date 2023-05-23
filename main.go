package main

import (
	"encoding/json"
	"fmt"
	"github.com/syssam/socialite/providers/apple"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type AppleIDToken struct {
	Email string `json:"email"`
	ID    string `json:"sub"`
}

func (a AppleIDToken) Valid() error {
	return nil
}

func main() {
	signingKey := `-----BEGIN PRIVATE KEY-----
	MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgFJofj/Dc9Pbz6qK9
	gpIHMLBoLbPg9SF0Dp8Bvaz+2uqgCgYIKoZIzj0DAQehRANCAARTt62+Ov4xzQDM
	pPNZwYteEYhxNhh6yDA4bg3LxkKHwyozlR6xybLcn6aQEtzXxtZn2UWAOG+mx4KL
	TycGpU4/
	-----END PRIVATE KEY-----`

	/*
		type JwtClaims struct {
			ID string `json:"id"`
			jwt.RegisteredClaims
		}

		idToken := "eyJraWQiOiJX\nNldjT0tCIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FwcGxlaWQuYXBwbGUuY29tIiwiYXVkIjoiYXBwLmZpbmltby5pb3MiLCJleHAiOjE2ODQ3NjM2MTYsImlhdCI6MTY4NDY3NzIxNiwic3ViIjoiMDAxNzYzLjQyODRlMDBiNGUxZTQxZmQ5ZjMzMTY3NmQwMzY2MDM3LjA0MzYiLCJhdF9\noYXNoIjoiQkNfQlF5ZlFXMkJ1eTFyV3BxaVpSZyIsImVtYWlsIjoieHA3bXp0OTd3cEBwcml2YXRlcmVsYXkuYXBwbGVpZC5jb20iLCJlbWFpbF92ZXJpZmllZCI6InRydWUiLCJpc19wcml2YXRlX2VtYWlsIjoidHJ1ZSIsImF1dGhfdGltZSI6MTY4NDY3NzE4OSwibm9uY2Vfc3VwcG9ydGVkIjp0cnVlf\nQ.YOxVw9vCdG304Jqt1nAgbaIvcyzIWxKfhJr5pNkHGJXnnFUWw7xF_XoacfJhu0Wo86W7slbXPBgUU0DWmj328iwf1i2RgvJub1b9WT-uewH_cc76CsXkRjDQZIE0_FLTKwmuMhWA3vdtmG1iADsg1MWqeVAVS7s3cwas0_zsGumrCjjP2ifXSOCYbTJGRWiuE4qhcVsRpdhMUJzhPADJBXDq93sq7_qPWMhi\nHGhE2Am45BF_Ckj42AaCq8RAmPt7lN3nzG3TpogtG-EkaXJmbi5fNhgImjE3vlBnqNHSQqOQEkgnUbayg7PziOlnlsE0blKzAfTtL_10fSqarflUTg"
		token, _, err := new(jwt.Parser).ParseUnverified(idToken, &AppleIDToken{})
		if err != nil {
			return
		}

		if claims, ok := token.Claims.(*AppleIDToken); ok {
			fmt.Println(claims)
		}

		return
	*/

	teamID := "FP45J2GN62"
	clientID := "app.finimo.ios"
	keyID := "M7S5Y4L9G5"

	secret, err := apple.CreateClientSecret(signingKey, teamID, clientID, keyID)
	if err != nil {
		fmt.Printf("createClientSecret Err: %v", err)
		return
	}

	data := url.Values{
		"client_id":     {clientID},
		"client_secret": {secret},
		"code":          {"c8e8526d1b3744f7da7e41495c4d9a38e.0.rrxwt.-JEKVVFXn0QCvdpeHEHL3A"},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {""},
	}

	resp, _ := http.Post(
		"https://appleid.apple.com/auth/token",
		"application/x-www-form-urlencoded",
		strings.NewReader(data.Encode()),
	)

	b, err := io.ReadAll(resp.Body)
	// b, err := ioutil.ReadAll(resp.Body)  Go.1.15 and earlier
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(string(b))

	defer resp.Body.Close()

	jsonMap := map[string]string{}
	err = json.NewDecoder(resp.Body).Decode(&jsonMap)
	if err != nil {
		fmt.Printf("Err: %v", err)
		return
	}
	fmt.Println(jsonMap)
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
}
