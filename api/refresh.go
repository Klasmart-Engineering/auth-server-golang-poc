package api

import (
	"crypto/rsa"
	"errors"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"kidsloop-auth-server-2/env"
	"kidsloop-auth-server-2/tokens"
	"kidsloop-auth-server-2/utils"
	"net/http"
	"net/url"
)

// RefreshHandler - Wrapper function called from the main HTTP Server Mutex
func RefreshHandler(w http.ResponseWriter, r *http.Request) {

	prevAccessCookie, _ := r.Cookie("access")
	prevRefreshCookie, err := r.Cookie("refresh")
	if err != nil {
		utils.ServerErrorResponse(http.StatusBadRequest, w, err)
		return
	}

	statusCode, accessCookie, refreshCookie, err := refreshExec(
		prevAccessCookie,
		prevRefreshCookie,
		env.JwtAlgorithm,
		env.JwtPublicKey,
		env.JwtPrivateKey,
	)

	if err != nil {
		utils.ServerErrorResponse(statusCode, w, err)
		return
	}

	// TODO: Improve this logic and perhaps move some of it inside the inner function `refreshExec`
	if statusCode != http.StatusOK {
		w.WriteHeader(statusCode)
		return
	}

	if accessCookie != nil {
		http.SetCookie(w, accessCookie)
	}
	if refreshCookie != nil {
		http.SetCookie(w, refreshCookie)
	}

	// Parse query URL to check for redirect
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		utils.ServerErrorResponse(500, w, err)
		return
	}
	if redirect := q.Get("redirect"); redirect != "" {
		// TODO: Add check to restrict to "domainRegex"
		http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
		return
	}

	w.WriteHeader(statusCode)
	return
}

// refreshExec - Internal function to validate existing tokens and/or replace them
// This function has been abstracted to be able to test it in isolation
func refreshExec(
	prevAccessCookie *http.Cookie,
	prevRefreshCookie *http.Cookie,
	jwtAlgorithm string,
	jwtPublicKey *rsa.PublicKey,
	jwtPrivateKey *rsa.PrivateKey,
) (int, *http.Cookie, *http.Cookie, error) {

	// Validate previous access token, if it is nil continue to validate refresh token
	if prevAccessCookie != nil {
		prevAccessToken, err := jwt.Parse(prevAccessCookie.Value, func(token *jwt.Token) (interface{}, error) {
			return jwtPublicKey, nil
		})
		if err != nil {
			if _, ok := err.(*jwt.ValidationError); !ok {
				// If error is not validation, fail with server error response
				return http.StatusInternalServerError, nil, nil, err
			}
		}

		// If access token is still valid, return 200 OK without any new cookies
		if prevAccessToken.Valid {
			return http.StatusOK, nil, nil, nil
		}
	}

	// Validate previous refresh token
	prevRefreshToken, err := jwt.Parse(prevRefreshCookie.Value, func(token *jwt.Token) (interface{}, error) {
		return jwtPublicKey, nil
	})
	if err != nil {
		if _, ok := err.(*jwt.ValidationError); !ok {
			// If error is not validation, fail with server error response
			return http.StatusInternalServerError, nil, nil, err
		}

	}

	// If refresh token (and thus implicitly also access token) is not valid, return 401
	if !prevRefreshToken.Valid {
		return http.StatusUnauthorized, nil, nil, nil
	}

	// If refresh token is still valid, re-issue access and refresh tokens
	prevRefreshClaims := prevRefreshToken.Claims.(jwt.MapClaims)
	token, exists := prevRefreshClaims["token"].(map[string]interface{})
	if !exists {
		return http.StatusBadRequest, nil, nil, errors.New("refresh token is not correct format")
	}

	userID := token["id"].(string)

	email, exists := token["email"].(string)
	if !exists {
		return http.StatusBadRequest, nil, nil, errors.New("could not extract email from previous access token")
	}

	// Generate new access token (with UserID)
	accessToken := new(tokens.AccessToken)
	accessToken.GenerateToken(jwtAlgorithm, jwtPrivateKey, email, &userID, env.JwtAccessTokenDuration)
	accessCookie := accessToken.CreateCookie(env.Domain, env.JwtAccessTokenDuration)

	// Generate a Refresh Token
	// TODO: Current behaviour generates a new UUID session ID each time. It should re-use prev ID which should be be tracked server-side
	refreshToken := new(tokens.RefreshToken)
	refreshToken.GenerateToken(jwtAlgorithm, jwtPrivateKey, uuid.NewString(), email, &userID, env.JwtRefreshTokenDuration)
	refreshCookie := refreshToken.CreateCookie(env.Domain, env.JwtRefreshTokenDuration)

	// If the access token is expired (or absent), but refresh token is valid, return 200 OK, with new access / refresh cookies
	return http.StatusOK, &accessCookie, &refreshCookie, nil
}
