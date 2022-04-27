package tokens

import (
	"github.com/golang-jwt/jwt/v4"
	"kidsloop-auth-server-2/test"
	"testing"
	"time"
)

func TestKidsloopToken_Parse(t *testing.T) {
	jwtDecodeSecret, _, _, testTokenString := test.LoadTestData()

	kidsloopToken := KidsloopToken{TokenString: &testTokenString}

	err := kidsloopToken.Parse(jwtDecodeSecret)
	if err != nil {
		t.Errorf("failed to Parse: %e", err)
	}
	if !kidsloopToken.Valid {
		t.Errorf("token is not valid")
	}
}

func TestKidsloopToken_GenerateToken(t *testing.T) {
	_, jwtEncodeSecret, _, _ := test.LoadTestData()
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
