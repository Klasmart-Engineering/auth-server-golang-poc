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
	"net/url"
)

func RefreshHandler(w http.ResponseWriter, r *http.Request) {
	jwtDecodeSecret, err := jwt.ParseRSAPublicKeyFromPEM([]byte(utils.PublicKey))
	if err != nil {
		utils.ServerErrorResponse(w, err)
		return
	}
	jwtEncodeSecret, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(utils.PrivateKey))
	if err != nil {
		utils.ServerErrorResponse(w, err)
		return
	}

	// Validate previous access token
	prevAccessTokenCookie, _ := r.Cookie("access")
	if prevAccessTokenCookie != nil {
		prevAccessToken, err := jwt.Parse(prevAccessTokenCookie.Value, func(token *jwt.Token) (interface{}, error) {
			return 	jwtDecodeSecret, nil
		})
		if err != nil {
			if _, ok := err.(*jwt.ValidationError); !ok {
				// If error is not validation, fail with server error response
				utils.ServerErrorResponse(w, err)
				return
			}
		}

		// If access token is still valid, return empty 200
		if prevAccessToken.Valid {
			w.WriteHeader(200)
			return
		}
	}


	// validate previous refresh token
	prevRefreshTokenCookie, err := r.Cookie("refresh")
	if err != nil {
		log.Printf("Cannot find refresh token")
		utils.ServerErrorResponse(w, err)
		return
	}
	prevRefreshToken, err := jwt.Parse(prevRefreshTokenCookie.Value, func(token *jwt.Token) (interface{}, error) {
		return 	jwtDecodeSecret, nil
	})
	if err != nil {
		utils.ServerErrorResponse(w, err)
		return
	}

	// If refresh token (and implicitly access token) is not valid return 401
	if !prevRefreshToken.Valid {
		w.WriteHeader(401)
		return
	}

	// If refresh token is still valid, re-issue access and refresh tokens
	prevRefreshClaims := prevRefreshToken.Claims.(jwt.MapClaims)
	token, exists := prevRefreshClaims["token"].(map[string]interface{})
	if !exists {
		utils.ServerErrorResponse(w, errors.New("refresh token is not correct format"))
		return
	}

	userID := token["id"].(string)

	email, exists := token["email"].(string)
	if !exists {
		utils.ServerErrorResponse(w, errors.New("could not extract email from previous access token"))
		return
	}

	// Generate new access token (with UserID)
	accessToken := new(tokens.AccessToken)
	accessToken.GenerateToken(env.JwtAlgorithm, jwtEncodeSecret, email, &userID, env.JwtAccessTokenDuration)
	accessCookie := accessToken.CreateCookie(env.Domain, env.JwtAccessTokenDuration)
	http.SetCookie(w, &accessCookie)

	//Generate a Refresh Token
	refreshToken := new(tokens.RefreshToken)
	refreshToken.GenerateToken(env.JwtAlgorithm, jwtEncodeSecret, uuid.NewString(), email, &userID, env.JwtRefreshTokenDuration)
	refreshCookie := refreshToken.CreateCookie(env.Domain, env.JwtRefreshTokenDuration)
	http.SetCookie(w, &refreshCookie)

	// Parse query URL to check for redirect
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		utils.ServerErrorResponse(w, err)
		return
	}
	if redirect := q.Get("redirect"); redirect != "" {
		// TODO: Add check to restrict to "domainRegex"
		http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
		return
	}

	w.WriteHeader(200)
	return
}