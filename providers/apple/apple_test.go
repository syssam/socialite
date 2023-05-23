package apple

import (
	"fmt"
	"testing"
)

var teamID = ""
var clientID = ""
var keyID = ""
var signingKey = ``
var authCode = ""

func TestCreateClientSecret(t *testing.T) {
	clientSecret, err := CreateClientSecret(signingKey, teamID, clientID, keyID)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(clientSecret)
}

func TestGetUserByAuthorizationCode(t *testing.T) {
	clientSecret, err := CreateClientSecret(signingKey, teamID, clientID, keyID)
	if err != nil {
		fmt.Println(err)
		return
	}
	p := NewProvider(clientID, clientSecret, "")
	user, err := p.GetUserByAuthorizationCode(authCode)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(user)
}
