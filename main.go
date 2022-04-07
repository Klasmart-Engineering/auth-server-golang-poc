package main

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/rs/cors"
	"net/http"
	"strings"
)

var privateKey = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`

var publicKey = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2WHjHUr9GAUlpk+5kmZW
zFmQpr1Bw/glVgaV4981sfjtVUn4oUYdgTmNfmLZGmgowBq3AbsgbB6h5ZDpFW0e
Yvz/EyBOxHpVGYLwwnNgriIWSU/Rk7tFOiQgmJ5aZaporBNyNBD/8MT/CIfSM30n
0DDRnbRyYXI67dZTLxguvmxYuabhWzLpi2ZjjsoWLEYZCJcLTJQdOPbKSrFl6rF+
m7H+FGRdhcRohNov0BfPo4K2sCOOaR2BPatrtoxC50FLwgsOlvpPeorNalzhz+th
fz9wy07qWokK1uvrQgEKJDMkrxDkbZdTNiAF2xKePedtWhs8moWEsN9uV7xyOWzr
xBocodv6T8Tqf6kxZgstuNAf2mluzAxTkkT4P0Gx5E+bkDt6d3w4/iXY7rpdDC7h
F4PnhE6Ii7WcRLNKPQQ3HoY01VXSh9CTUZnZmGjCX3UQtL5JEiMUjlWXddOh1FIY
AIzjd6EIYu9N15QmQaCdjp2+k2cd/MgHwCoYqRA6+Vq7tbt0HyQdu54uj/KMnXbB
DLN7HO73ilC9nukNMzgCRsSTS+pHMoh8GzDH39zbepsU5gLG0b7IJUpPxWpxYZaG
//PICaY7uVhnP00QNS1bng6+WsyH4OJYDPGmrOPGaWzb8nSFx2WoWxsZgktAgGy+
DdmM7ZvGV75b8drdbVhUgOECAwEAAQ==
-----END PUBLIC KEY-----`

type transferJSON struct {
	Token *string `json:"token"`
}

func main() {

	c := cors.New(cors.Options{
		AllowedOrigins: []string{"https://kidskube-dev.kidsloop.live"},
		AllowCredentials: true,
		AllowedHeaders: []string{"Authorization", "Content-Type"},
		MaxAge: 60 * 60 * 24, // One day
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/express/server-health", ServerHealth)
	mux.HandleFunc("/transfer", TransferHandler)
	mux.HandleFunc("/switch", SwitchHandler)
	//mux.HandleFunc("/refresh", Refresh)
	//mux.HandleFunc("/signout", SignOut)
	handler := c.Handler(mux)
	http.ListenAndServe(":8080", handler)
}

func ServerHealth(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		w.WriteHeader(http.StatusOK)
		return
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}

func TransferHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		d := json.NewDecoder(r.Body)
		var payload transferJSON
		err := d.Decode(&payload)
		if err != nil {
			ServerErrorResponse(w, err)
			return
		}

		//validate token
		jwtVerifyKey, err :=jwt.ParseRSAPublicKeyFromPEM([]byte(publicKey))
		if err != nil {
			ServerErrorResponse(w, err)
			return
		}
		parts := strings.Split(*payload.Token, ".")
		err = jwt.SigningMethodRS512.Verify(strings.Join(parts[0:2], "."), parts[2], jwtVerifyKey)
		if err != nil {
			ServerErrorResponse(w, err)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Token is valid!"))
		return
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}

func SwitchHandler(w http.ResponseWriter, r *http.Request) {
	//jwtSecret := []byte("KidsloopAuth")
	jwtSecret, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKey))
	if err != nil {
		ServerErrorResponse(w, err)
		return
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.MapClaims{
		"id": "2646862c-bb96-49c0-8d95-ea9cb781d255",
		"email": "matthew.revell@opencredo.com",
		"iss": "kidsloop",
	})
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		ServerErrorResponse(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(tokenString))

}

func ServerErrorResponse(w http.ResponseWriter, err error){
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(w, err.Error())
	return
}