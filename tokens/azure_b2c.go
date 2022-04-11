package tokens

import (
	"encoding/json"
	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"io/ioutil"
	"net/http"
)

type AzureB2CToken struct {
	token *jwt.Token
}

func azureKeyFunc(token *jwt.Token) (interface{}, error) {
	//TODO: Construct URL from env var and config
	keyLookupResponse, err := http.Get("https://login.loadtest.kidsloop.live/8d922fec-c1fc-4772-b37e-18d2ce6790df/b2c_1a_relying_party_sign_up_log_in/discovery/v2.0/keys")
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(keyLookupResponse.Body)
	if err != nil {
		return nil, err
	}

	jwksJSON := json.RawMessage(body)
	jkws, err := keyfunc.NewJSON(jwksJSON)
	if err != nil {
		return nil, err
	}

	return jkws.Keyfunc(token)
}

func ParseProviderToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, azureKeyFunc)
	if err != nil {
		return nil, err
	}

	return token, nil
}