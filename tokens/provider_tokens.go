package tokens

import (
	"encoding/json"
	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"io/ioutil"
	"net/http"
)

type BearerToken interface {
	KeyFunc(token *jwt.Token) (interface{}, error)
}

type AzureB2CToken struct {
	TokenString string
	Token *jwt.Token
}

func (t *AzureB2CToken) KeyFunc(token *jwt.Token) (interface{}, error) {
	//TODO: Construct URL from env var and config
	//TODO: Improve to look more like this example https://blog.jonathanchannon.com/2022-01-29-azuread-golang/
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

func (t *AzureB2CToken) Parse() error {
	token, err := jwt.Parse(t.TokenString, t.KeyFunc)
	if err != nil {
		return err
	}
	t.Token = token

	return nil
}