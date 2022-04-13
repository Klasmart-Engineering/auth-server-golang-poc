package api

import (
	"errors"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"kidsloop-auth-server-2/tokens"
	"kidsloop-auth-server-2/utils"
	"log"
	"net/http"
	"strings"
	"time"
)

type AccessClaims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
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


func TransferHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		// Validate Identity Bearer Token
		//TODO: Need to be able to manage AMS as well as AzureB2C
		bearerTokenString := strings.TrimPrefix(r.Header.Get("authorization"), "Bearer ")
		providerToken := tokens.AzureB2CToken{
			TokenString: bearerTokenString,
		}
		err := providerToken.Parse()
		if err != nil {
			utils.ServerErrorResponse(w, err)
			return
		}

		if !providerToken.Valid {
			w.WriteHeader(401)
			return
		}

		bearerClaims := providerToken.Claims.(jwt.MapClaims)
		email, exists := bearerClaims["email"]
		if !exists {
			utils.ServerErrorResponse(w, errors.New("could not extract email from provider token"))
			return
		}

		log.Printf("Token is valid!")

		// Prepare to sign tokens
		jwtSecret, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(utils.PrivateKey))

		// Generate an Access Token
		if err != nil {
			utils.ServerErrorResponse(w, err)
			return
		}

		accessToken := jwt.NewWithClaims(jwt.SigningMethodRS512, &AccessClaims{
			Email: email.(string),
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)), //TODO: Confirm timeframe
				Issuer: "kidsloop",
			},
		})

		accessTokenString, err := accessToken.SignedString(jwtSecret)
		if err != nil {
			utils.ServerErrorResponse(w, err)
			return
		}
		accessCookie := http.Cookie{
			Name: "access",
			Value: accessTokenString,
			Domain: "localhost", //TODO: Use env var etc.
			Path: "/",
			MaxAge: 900,
			Expires: time.Now().Add(15 * time.Minute), //TODO: Confirm the timeframe
		}
		http.SetCookie(w, &accessCookie)

		//Generate a Refresh Token
		refreshToken := jwt.NewWithClaims(jwt.SigningMethodRS512, &RefreshClaims{
			SessionID: uuid.NewString(),
			Token: RefreshClaimToken{
				Email: email.(string),
			},
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt: jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(14 * 24 * time.Hour)), //TODO: Confirm timeframe
				Issuer: "kidsloop",
				Subject: "refresh",
			},
		})

		refreshTokenString, err := refreshToken.SignedString(jwtSecret)
		if err != nil {
			utils.ServerErrorResponse(w, err)
			return
		}

		refreshCookie := http.Cookie{
			Name: "refresh",
			Value: refreshTokenString,
			Domain: "localhost", //TODO: Use env var etc.
			Path: "/refresh",
			MaxAge: 1206000,
			Expires: time.Now().Add(1206000), //TODO: Confirm the timeframe
			HttpOnly: true,
			Secure: true,
		}
		http.SetCookie(w, &refreshCookie)

		w.WriteHeader(http.StatusOK)
		return
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}
