package api

import (
	"errors"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"kidsloop-auth-server-2/env"
	"kidsloop-auth-server-2/tokens"
	"kidsloop-auth-server-2/utils"
	"log"
	"net/http"
	"strings"
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
		bearerTokenString := strings.TrimPrefix(r.Header.Get("authorization"), "Bearer ")
		providerToken := tokens.AzureB2CToken{
			TokenString: bearerTokenString,
		}
		err := providerToken.Parse(*env.AzureKeySet)
		if err != nil {
			utils.ServerErrorResponse(w, err)
			return
		}

		if !providerToken.Valid {
			w.WriteHeader(401)
			return
		}

		bearerClaims := providerToken.Claims.(jwt.MapClaims)
		email, exists := bearerClaims["email"].(string)
		if !exists {
			utils.ServerErrorResponse(w, errors.New("could not extract email from provider token"))
			return
		}

		log.Printf("Provider Token is valid!")

		// Prepare to sign tokens
		jwtEncodeSecret, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(utils.PrivateKey))

		if err != nil {
			utils.ServerErrorResponse(w, err)
			return
		}

		// Generate an Access Token
		accessToken := new(tokens.AccessToken)
		accessToken.GenerateToken(env.JwtAlgorithm, jwtEncodeSecret, email, nil, env.JwtAccessTokenDuration)
		accessCookie := accessToken.CreateCookie(env.Domain, env.JwtAccessTokenDuration)
		http.SetCookie(w, &accessCookie)

		//Generate a Refresh Token
		refreshToken := new(tokens.RefreshToken)
		refreshToken.GenerateToken(env.JwtAlgorithm, jwtEncodeSecret, uuid.NewString(), email, nil, env.JwtRefreshTokenDuration)
		refreshCookie := refreshToken.CreateCookie(env.Domain, env.JwtRefreshTokenDuration)
		http.SetCookie(w, &refreshCookie)

		w.WriteHeader(http.StatusOK)
		return
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}
