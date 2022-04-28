package api

import (
	"crypto/rsa"
	"errors"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwk"
	"kidsloop-auth-server-2/env"
	"kidsloop-auth-server-2/tokens"
	"kidsloop-auth-server-2/utils"
	"log"
	"net/http"
	"strings"
	"time"
)

// TransferHandler - Wrapper function called from the main HTTP Server Mutex
func TransferHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		bearerTokenString := strings.TrimPrefix(r.Header.Get("authorization"), "Bearer ")
		email, valid, err := validateBearerToken(bearerTokenString, env.AzureKeySet)
		if err != nil {
			utils.ServerErrorResponse(http.StatusBadRequest, w, err)
		}
		if !valid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		statusCode, accessCookie, refreshCookie, err := transferExec(
			*email,
			env.Domain,
			env.JwtAlgorithm,
			env.JwtPrivateKey,
			env.JwtAccessTokenDuration,
			env.JwtRefreshTokenDuration,
		)
		if err != nil {
			utils.ServerErrorResponse(statusCode, w, err)
		}

		if statusCode != http.StatusOK {
			w.WriteHeader(statusCode)
			return
		}

		http.SetCookie(w, accessCookie)
		http.SetCookie(w, refreshCookie)
		w.WriteHeader(statusCode)
		return
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}

// validateBearerToken - Internal function to validate the bearer token provided by Azure (or other ID provider)
// This function has been abstracted to be able to test it in isolation
// TODO: Add a test for this function
func validateBearerToken(bearerTokenString string, keySet *jwk.Set) (*string, bool, error) {
	// Validate Identity Bearer Token
	providerToken := tokens.AzureB2CToken{
		TokenString: bearerTokenString,
	}
	err := providerToken.Parse(*keySet)
	if err != nil {
		return nil, false, err
	}

	if !providerToken.Valid {
		return nil, false, nil
	}

	bearerClaims := providerToken.Claims.(jwt.MapClaims)
	email, exists := bearerClaims["email"].(string)
	if !exists {
		return nil, true, errors.New("could not extract email from provider token")
	}

	log.Printf("Provider Token is valid!")
	return &email, true, nil
}

// transferExec - Internal function to issue a new access token and refresh token
// This function has been abstracted to be able to test it in isolation
func transferExec(email string, domain string, jwtAlgorithm string, jwtPrivateKey *rsa.PrivateKey, jwtAccessTokenDuration time.Duration, jwtRefreshTokenDuration time.Duration) (int, *http.Cookie, *http.Cookie, error) {
	// Generate an Access Token
	accessToken := new(tokens.AccessToken)
	accessToken.GenerateToken(jwtAlgorithm, jwtPrivateKey, email, nil, jwtAccessTokenDuration)
	accessCookie := accessToken.CreateCookie(domain, jwtAccessTokenDuration)

	//Generate a Refresh Token
	refreshToken := new(tokens.RefreshToken)
	refreshToken.GenerateToken(jwtAlgorithm, jwtPrivateKey, uuid.NewString(), email, nil, jwtRefreshTokenDuration)
	refreshCookie := refreshToken.CreateCookie(domain, jwtRefreshTokenDuration)

	return http.StatusOK, &accessCookie, &refreshCookie, nil
}
