package test

import (
	"crypto/rsa"
	"github.com/golang-jwt/jwt/v4"
	"log"
	"time"
)

type Claims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

func LoadTestData() (*rsa.PublicKey, *rsa.PrivateKey, *jwt.Token, string) {
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(PublicKey))
	if err != nil {
		log.Fatalf("failed to load rsa public key: %e", err)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(PrivateKey))
	if err != nil {
		log.Fatalf("failed to load rsa private key: %e", err)
	}

	testClaims := Claims{
		Email: "someone@somewhere.com",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "test",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
	}

	testToken := jwt.NewWithClaims(jwt.SigningMethodRS512, testClaims)
	testTokenString, err := testToken.SignedString(privateKey)
	if err != nil {
		log.Fatalf("failed to sign test token: %e", err)
	}

	return publicKey, privateKey, testToken, testTokenString
}