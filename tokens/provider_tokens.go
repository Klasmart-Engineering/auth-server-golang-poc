package tokens

import (
	"crypto/rsa"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/jwk"
)

type ProviderToken interface {
	keyFunc(token *jwt.Token) (interface{}, error)
}

type AzureB2CToken struct {
	TokenString string
	*jwt.Token
}

func (t *AzureB2CToken) Parse(keySet jwk.Set) error {
	token, err := jwt.Parse(t.TokenString, func(token *jwt.Token) (interface{}, error) {
		//keySet, err := jwk.Fetch(context.Background(), fmt.Sprintf("https://%s/%s/%s/discovery/%s/keys", env.AzureB2cDomain, env.AzureB2cTenantId, env.AzureB2cPolicyName, env.AzureB2cVersion))
		//if err != nil {
		//	return nil, err
		//}

		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid header not found")
		}

		key, ok := keySet.LookupKeyID(kid)
		if !ok {
			return nil, fmt.Errorf("key %v not found", kid)
		}
		publicKey := &rsa.PublicKey{}
		err := key.Raw(publicKey)
		if err != nil {
			return nil, fmt.Errorf("could not parse pubkey")
		}

		return publicKey, nil
	})

	if err != nil {
		if _, ok := err.(*jwt.ValidationError); !ok {
			// If error is not validation, return error
			return err
		}
	}
	t.Token = token

	return nil
}
