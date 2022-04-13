package tokens

import (
	"crypto/rsa"
	"github.com/golang-jwt/jwt/v4"
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

func (t *RefreshToken) GenerateToken(jwtEncodeSecret *rsa.PrivateKey, sessionID string, email string, userID *string) error {
	claims := RefreshClaims{
		SessionID: sessionID,
		Token: RefreshClaimToken{
			UserID: userID,
			Email: email,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(14 * 24 * time.Hour)), // TODO: Confirm timeframe
			Issuer: "kidsloop",
		},
	}

	err := t.KidsloopToken.GenerateToken(jwtEncodeSecret, claims)
	if err != nil {
		return err
	}

	return nil
}

func (t *RefreshToken) CreateCookie(domain string) http.Cookie {
	cookie := http.Cookie{
		Name:     "refresh",
		Value:    *t.TokenString,
		Domain:   domain,
		Path:     "/refresh",
		MaxAge:   1206000,
		Expires:  time.Now().Add(1206000), //TODO: Confirm the timeframe
		HttpOnly: true,
		Secure:   true,
	}

	return cookie
}