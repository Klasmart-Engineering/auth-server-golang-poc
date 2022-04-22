package test

import (
	"crypto/rsa"
	"github.com/golang-jwt/jwt/v4"
	"kidsloop-auth-server-2/utils"
	"log"
	"time"
)

func LoadTestData() (*rsa.PublicKey, *rsa.PrivateKey, *jwt.Token, string) {
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(utils.PublicKey))
	if err != nil {
		log.Fatalf("failed to load rsa public key: %e", err)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(utils.PrivateKey))
	if err != nil {
		log.Fatalf("failed to load rsa private key: %e", err)
	}

	testToken := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.RegisteredClaims{Issuer: "test", ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute))})
	testTokenString, err := testToken.SignedString(privateKey)
	if err != nil {
		log.Fatalf("failed to sign test token: %e", err)
	}

	return publicKey, privateKey, testToken, testTokenString
}
