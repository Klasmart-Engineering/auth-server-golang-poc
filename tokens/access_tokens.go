package tokens

import (
	"crypto/rsa"
	"github.com/golang-jwt/jwt/v4"
	"net/http"
	"time"
)

type AccessToken struct {
	KidsloopToken
}

type AccessClaims struct {
	UserID *string `json:"id,omitempty"`
	Email string `json:"email"`
	jwt.RegisteredClaims
}

func (t *AccessToken) GenerateToken(jwtEncodeSecret *rsa.PrivateKey, email string, userID *string) error {
	claims := AccessClaims{
		UserID: userID,
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)), // TODO: Confirm timeframe
			Issuer: "kidsloop",
		},
	}

	err := t.KidsloopToken.GenerateToken(jwtEncodeSecret, claims)
	if err != nil {
		return err
	}

	return nil
}

func (t *AccessToken) CreateCookie(domain string) http.Cookie {
	cookie := http.Cookie{
		Name: "access",
		Value: *t.TokenString,
		Domain: domain,
		Path: "/",
		MaxAge: 900,
		Expires: time.Now().Add(15 * time.Minute), //TODO: Confirm the timeframe
	}

	return cookie
}

