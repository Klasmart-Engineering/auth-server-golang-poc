package api

import (
	"errors"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"kidsloop-auth-server-2/utils"
	"log"
	"net/http"
	"net/url"
	"time"
)

func RefreshHandler(w http.ResponseWriter, r *http.Request) {
	jwtDecodeSecret, err := jwt.ParseRSAPublicKeyFromPEM([]byte(utils.PublicKey))
	jwtEncodeSecret, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(utils.PrivateKey))

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


	//validate previous refresh token
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
	accessClaims := SwitchClaims{
		UserID: userID,
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)), // TODO: Confirm timeframe
			Issuer: "kidsloop",
		},
	}
	// If refresh token is still valid, re-issue access and refresh tokens
	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS512, &accessClaims)
	accessTokenString, err := accessToken.SignedString(jwtEncodeSecret)
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
			UserID: &userID,
			Email: email,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(14 * 24 * time.Hour)), //TODO: Confirm timeframe
			Issuer: "kidsloop",
			Subject: "refresh",
		},
	})

	refreshTokenString, err := refreshToken.SignedString(jwtEncodeSecret)
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