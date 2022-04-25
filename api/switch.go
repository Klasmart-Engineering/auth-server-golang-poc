package api

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"io"
	"kidsloop-auth-server-2/env"
	"kidsloop-auth-server-2/tokens"
	"kidsloop-auth-server-2/utils"
	"net/http"
	"time"
)

type switchPayload struct {
	UserID string `json:"user_id"`
}

func SwitchHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Create a DBConnector interface that connects to an actual DB.
	db := new(utils.DummyDBConnector)
	prevAccessCookie, err := r.Cookie("access")
	if err != nil {
		utils.ServerErrorResponse(w, err)
		return
	}
	statusCode, accessCookie, refreshCookie, err := switchExec(
		db,
		r.Body,
		prevAccessCookie,
		env.Domain,
		env.JwtAlgorithm,
		env.JwtPublicKey,
		env.JwtPrivateKey,
		env.JwtAccessTokenDuration,
		env.JwtRefreshTokenDuration,
	)
	if err != nil {
		utils.ServerErrorResponse(w, err)
		return
	}

	if statusCode != http.StatusOK {
		w.WriteHeader(statusCode)
		return
	}

	http.SetCookie(w, accessCookie)
	http.SetCookie(w, refreshCookie)
	w.WriteHeader(statusCode)
	return
}


func switchExec(
	db utils.DBConnector,
	body io.ReadCloser,
	prevAccessCookie *http.Cookie,
	domain string,
	jwtAlgorithm string,
	jwtPublicKey *rsa.PublicKey,
	jwtPrivateKey *rsa.PrivateKey,
	jwtAccessTokenDuration time.Duration,
	jwtRefreshTokenDuration time.Duration,
	) (int, *http.Cookie, *http.Cookie, error) {

	var payload switchPayload
	d := json.NewDecoder(body)
	err := d.Decode(&payload)
	if err != nil {
		return http.StatusBadRequest, nil, nil, errors.New("unable to decode request body JSON")
	}
	db.ConnectToDB()
	if !db.UserExists(payload.UserID) {
		return http.StatusUnauthorized, nil, nil, nil
	}

	// Validate previous access token

	prevAccessToken := new(tokens.AccessToken)
	prevAccessToken.TokenString = &prevAccessCookie.Value
	err = prevAccessToken.Parse(jwtPublicKey)
	if err != nil {
		return http.StatusBadRequest, nil, nil, err
	}

	if !prevAccessToken.Valid {
		return http.StatusUnauthorized, nil, nil, nil
	}

	prevAccessClaims := prevAccessToken.Claims.(jwt.MapClaims)
	email, exists := prevAccessClaims["email"].(string)
	if !exists {
		return http.StatusBadRequest, nil, nil, errors.New("could not extract email from previous access token")
	}

	// Generate new access token (with UserID)
	accessToken := new(tokens.AccessToken)
	err = accessToken.GenerateToken(jwtAlgorithm, jwtPrivateKey, email, &payload.UserID, jwtAccessTokenDuration)
	if err != nil {
		return http.StatusInternalServerError, nil, nil, err
	}
	accessCookie := accessToken.CreateCookie(domain, jwtAccessTokenDuration)

	//Generate a Refresh Token
	refreshToken := new(tokens.RefreshToken)
	err = refreshToken.GenerateToken(jwtAlgorithm, jwtPrivateKey, uuid.NewString(), email, &payload.UserID, jwtRefreshTokenDuration)
	if err != nil {
		return http.StatusInternalServerError, nil, nil, err
	}
	refreshCookie := refreshToken.CreateCookie(domain, jwtRefreshTokenDuration)

	return http.StatusOK, &accessCookie, &refreshCookie, nil
}
