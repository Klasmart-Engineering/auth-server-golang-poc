package api

import (
	"encoding/json"
	"errors"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"kidsloop-auth-server-2/utils"
	"net/http"
	"time"
)

type switchPayload struct {
	UserID string `json:"user_id"`
}

type SwitchClaims struct {
	UserID string `json:"id"`
	Email string `json:"email"`
	jwt.RegisteredClaims
}

func SwitchHandler(w http.ResponseWriter, r *http.Request) {
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

	db := utils.DBConnector{
		Connector: utils.DummyDBConnector{},
	}

	// TODO: Move everything under here to a separate method so it can be tested
	var payload switchPayload
	d := json.NewDecoder(r.Body)
	d.Decode(&payload)
	db.Connector.ConnectToDB()
	if !db.Connector.UserExists(payload.UserID) {
		utils.ServerErrorResponse(w, errors.New("user ID is not valid"))
		return
	}

	// Validate previous access token
	prevAccessTokenCookie, err := r.Cookie("access")
	if err != nil {
		utils.ServerErrorResponse(w, err)
		return
	}
	prevAccessToken, err := jwt.Parse(prevAccessTokenCookie.Value, func(token *jwt.Token) (interface{}, error) {
		return 	jwtDecodeSecret, nil
	})
	if err != nil {
		utils.ServerErrorResponse(w, err)
		return
	}
	if !prevAccessToken.Valid {
		w.WriteHeader(401)
		return
	}
	prevAccessClaims := prevAccessToken.Claims.(jwt.MapClaims)
	email, exists := prevAccessClaims["email"]
	if !exists {
		utils.ServerErrorResponse(w, errors.New("could not extract email from previous access token"))
		return
	}

	// Generate new access token (with UserID)
	accessClaims := SwitchClaims{
		UserID: payload.UserID,
		Email: email.(string),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)), // TODO: Confirm timeframe
			Issuer: "kidsloop",
		},
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodRS512, accessClaims)

	accessTokenString, err := accessToken.SignedString(jwtEncodeSecret)
	if err != nil {
		utils.ServerErrorResponse(w, err)
		return
	}
	accessCookie := http.Cookie{
		Name: "access",
		Value: accessTokenString,
		Domain: "loadtest.kidsloop.live", //TODO: Use env var etc.
		Path: "/",
		MaxAge: 900,
		Expires: time.Now().Add(15 * time.Minute), //TODO: Confirm the timeframe
	}
	http.SetCookie(w, &accessCookie)

	//Generate a Refresh Token
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodRS512, &RefreshClaims{
		SessionID: uuid.NewString(),
		Token: RefreshClaimToken{
			UserID: &payload.UserID,
			Email: email.(string),
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
		Name: "refesh",
		Value: refreshTokenString,
		Domain: "loadtest.kidsloop.live", //TODO: Use env var etc.
		Path: "/refresh",
		MaxAge: 1206000,
		Expires: time.Now().Add(1206000), //TODO: Confirm the timeframe
		HttpOnly: true,
		Secure: true,
	}
	http.SetCookie(w, &refreshCookie)
	w.WriteHeader(http.StatusOK)
	return
}
