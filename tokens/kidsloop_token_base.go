package tokens

import (
	"crypto/rsa"
	"github.com/golang-jwt/jwt/v4"
	"net/http"
	"time"
)

type KidsloopToken struct {
	TokenString *string
	*jwt.Token
}

type KidsloopTokenIface interface {
	Parse() error
	GenerateToken(claims jwt.Claims, duration time.Duration) error
	CreateCookie(domain string, duration time.Duration) http.Cookie
}

func (t *KidsloopToken) Parse(jwtDecodeSecret *rsa.PublicKey) error {
	token, err := jwt.Parse(*t.TokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtDecodeSecret, nil
	})

	if err != nil {
		if err != nil {
			if _, ok := err.(*jwt.ValidationError); !ok {
				// If error is not validation, return error
				return err
			}
		}
	}
	t.Token = token

	return nil
}

func (t *KidsloopToken) GenerateToken(jwtSigningMethod string, jwtEncodeSecret *rsa.PrivateKey, claims jwt.Claims) error {
	token := jwt.NewWithClaims(jwt.GetSigningMethod(jwtSigningMethod), claims)
	tokenString, err := token.SignedString(jwtEncodeSecret)
	if err != nil {
		return err
	}
	t.Token = token
	t.TokenString = &tokenString
	return nil
}
