package api

import (
	"encoding/json"
	"kidsloop-auth-server-2/tokens"
	"kidsloop-auth-server-2/utils"
	"log"
	"net/http"
	"strings"
)

type tokenJSON struct {
	Token string `json:"token"`
}

func TransferHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		authHeader := strings.TrimPrefix(r.Header.Get("authorization"), "Bearer ")
		log.Printf("Auth Header: %v", authHeader)
		d := json.NewDecoder(r.Body)
		var idProviderToken tokenJSON
		err := d.Decode(&idProviderToken)
		if err != nil {
			utils.ServerErrorResponse(w, err)
			return
		}

		//validate token - TODO: Be able to load correct keys for each provider
		//jwtVerifyKey, err :=jwt.ParseRSAPublicKeyFromPEM([]byte(utils.PublicKey))
		//if err != nil {
		//	utils.ServerErrorResponse(w, err)
		//	return
		//}
		//
		//
		//parts := strings.Split(*idProviderToken.Token, ".")
		//err = jwt.SigningMethodRS512.Verify(strings.Join(parts[0:2], "."), parts[2], jwtVerifyKey)
		//if err != nil {
		//	utils.ServerErrorResponse(w, err)
		//	return
		//}
		providerToken, err := tokens.ParseProviderToken(idProviderToken.Token)
		if err != nil {
			utils.ServerErrorResponse(w, err)
			return
		}

		log.Printf("Token: %v", providerToken)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Token is valid!"))
		return
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}
