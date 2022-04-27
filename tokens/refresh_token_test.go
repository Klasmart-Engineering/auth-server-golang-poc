package tokens

import (
	"kidsloop-auth-server-2/test"
	"testing"
	"time"
)

func TestRefreshToken_GenerateToken(t *testing.T) {
	_, jwtEncodeSecret, _, _ := test.LoadTestData()
	refreshToken := RefreshToken{}
	userID := "someuserID"
	err := refreshToken.GenerateToken("RS512", jwtEncodeSecret, "somesessionID", "somebody@kidsloop.live", &userID, 5*time.Minute)
	if err != nil {
		t.Errorf("failed to genertate token: %e", err)
	}
	if refreshToken.Token == nil {
		t.Errorf("token should be set, but it is nil")
	}
	if refreshToken.TokenString == nil {
		t.Errorf("token string should exist, but it is nil")
	}
}

func TestRefreshToken_CreateCookie(t *testing.T) {
	_, jwtEncodeSecret, _, _ := test.LoadTestData()
	refreshToken := RefreshToken{}
	userID := "someuserID"
	err := refreshToken.GenerateToken("RS512", jwtEncodeSecret, "somesessionID", "somebody@kidsloop.live", &userID, 5*time.Minute)
	if err != nil {
		t.Errorf("failed to genertate token: %e", err)
	}

	refreshCookie := refreshToken.CreateCookie("localhost", 5*time.Minute)
	if refreshCookie.Name != "refresh" {
		t.Errorf("cookie name not correct")
	}
	if refreshCookie.Path != "/refresh" {
		t.Errorf("cookie path is incorrect")
	}
	if refreshCookie.Value != *refreshToken.TokenString {
		t.Errorf("cookie value does not match the token string")
	}
}
