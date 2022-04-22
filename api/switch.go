package api

import (
	"encoding/json"
	"errors"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"kidsloop-auth-server-2/env"
	"kidsloop-auth-server-2/tokens"
	"kidsloop-auth-server-2/utils"
	"net/http"
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
	prevAccessToken := new(tokens.AccessToken)
	prevAccessToken.TokenString = &prevAccessTokenCookie.Value
	prevAccessToken.Parse(jwtDecodeSecret)

	if !prevAccessToken.Valid {
		w.WriteHeader(401)
		return
	}

	prevAccessClaims := prevAccessToken.Claims.(jwt.MapClaims)
	email, exists := prevAccessClaims["email"].(string)
	if !exists {
		utils.ServerErrorResponse(w, errors.New("could not extract email from previous access token"))
		return
	}

	// Generate new access token (with UserID)
	accessToken := new(tokens.AccessToken)
	accessToken.GenerateToken(env.JwtAlgorithm, jwtEncodeSecret, email, &payload.UserID, env.JwtAccessTokenDuration)
	accessCookie := accessToken.CreateCookie(env.Domain, env.JwtAccessTokenDuration)
	http.SetCookie(w, &accessCookie)

	//Generate a Refresh Token
	refreshToken := new(tokens.RefreshToken)
	refreshToken.GenerateToken(env.JwtAlgorithm, jwtEncodeSecret, uuid.NewString(), email, &payload.UserID, env.JwtRefreshTokenDuration)
	refreshCookie := refreshToken.CreateCookie(env.Domain, env.JwtRefreshTokenDuration)
	http.SetCookie(w, &refreshCookie)

	w.WriteHeader(http.StatusOK)
	return
}
