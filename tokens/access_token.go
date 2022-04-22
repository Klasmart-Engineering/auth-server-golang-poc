package tokens

import (
	"crypto/rsa"
	"github.com/golang-jwt/jwt/v4"
	"kidsloop-auth-server-2/env"
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

func (t *AccessToken) GenerateToken(jwtSigningMethod string, jwtEncodeSecret *rsa.PrivateKey, email string, userID *string, duration time.Duration) error {
	claims := AccessClaims{
		UserID: userID,
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)), // TODO: Confirm timeframe
			Issuer: env.JwtIssuer,
		},
	}

	err := t.KidsloopToken.GenerateToken(jwtSigningMethod, jwtEncodeSecret, claims)
	if err != nil {
		return err
	}

	return nil
}

func (t *AccessToken) CreateCookie(domain string, duration time.Duration) http.Cookie {
	cookie := http.Cookie{
		Name:    "access",
		Value:   *t.TokenString,
		Domain:  domain,
		Path:    "/",
		MaxAge: int(duration.Seconds()),
		Expires: time.Now().Add(duration),
	}

	return cookie
}

