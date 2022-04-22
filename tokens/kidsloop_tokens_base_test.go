package tokens

import (
	"crypto/rsa"
	"github.com/golang-jwt/jwt/v4"
	"kidsloop-auth-server-2/utils"
	"log"
	"testing"
	"time"
)

func loadTestData() (*rsa.PublicKey, *rsa.PrivateKey, *jwt.Token, string) {
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

func TestParse(t *testing.T) {
	jwtDecodeSecret, _, _, testTokenString := loadTestData()

	kidsloopToken := KidsloopToken{TokenString: &testTokenString}

	err := kidsloopToken.Parse(jwtDecodeSecret)
	if err != nil {
		t.Errorf("failed to Parse: %e", err)
	}
	if !kidsloopToken.Valid {
		t.Errorf("token is not valid")
	}
}

func TestGenerateToken(t *testing.T) {
	_, jwtEncodeSecret, _, _ := loadTestData()
	kidsloopToken := KidsloopToken{}
	err := kidsloopToken.GenerateToken("RS512", jwtEncodeSecret, jwt.RegisteredClaims{Issuer: "test", ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute))})
	if err != nil {
		t.Errorf("failed to generate token")
	}
	if kidsloopToken.Token == nil {
		t.Errorf("token should be set, but it is nil")
	}
	if kidsloopToken.TokenString == nil {
		t.Errorf("token string should exist, but it is nil")
	}
}