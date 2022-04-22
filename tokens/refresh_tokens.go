package tokens

import (
	"crypto/rsa"
	"github.com/golang-jwt/jwt/v4"
	"kidsloop-auth-server-2/env"
	"net/http"
	"time"
)

type RefreshToken struct {
	KidsloopToken
}

type RefreshClaims struct {
	SessionID string `json:"session_id"`
	Token RefreshClaimToken `json:"token"`
	jwt.RegisteredClaims
}

type RefreshClaimToken struct {
	UserID *string `json:"id,omitempty"`
	Email string `json:"email"`
}

func (t *RefreshToken) GenerateToken(jwtSigningMethod string, jwtEncodeSecret *rsa.PrivateKey, sessionID string, email string, userID *string, duration time.Duration) error {
	claims := RefreshClaims{
		SessionID: sessionID,
		Token: RefreshClaimToken{
			UserID: userID,
			Email: email,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			Issuer: env.JwtIssuer,
		},
	}

	err := t.KidsloopToken.GenerateToken(jwtSigningMethod, jwtEncodeSecret, claims)
	if err != nil {
		return err
	}

	return nil
}

func (t *RefreshToken) CreateCookie(domain string, duration time.Duration) http.Cookie {
	cookie := http.Cookie{
		Name:     "refresh",
		Value:    *t.TokenString,
		Domain:   domain,
		Path:     "/refresh",
		MaxAge:   int(duration.Seconds()),
		Expires:  time.Now().Add(duration),
		HttpOnly: true,
		Secure:   true,
	}

	return cookie
}