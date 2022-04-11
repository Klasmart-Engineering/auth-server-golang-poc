package api

import (
	"github.com/golang-jwt/jwt/v4"
	"kidsloop-auth-server-2/utils"
	"net/http"
)

func SwitchHandler(w http.ResponseWriter, r *http.Request) {
	jwtSecret, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(utils.PrivateKey))
	if err != nil {
		utils.ServerErrorResponse(w, err)
		return
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.MapClaims{
		"id": "2646862c-bb96-49c0-8d95-ea9cb781d255",
		"email": "matthew.revell@opencredo.com",
		"iss": "kidsloop",
	})
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		utils.ServerErrorResponse(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(tokenString))
}
