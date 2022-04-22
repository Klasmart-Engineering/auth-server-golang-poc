package tokens

import (
	"kidsloop-auth-server-2/test"
	"testing"
	"time"
)

func TestAccessToken_GenerateToken(t *testing.T) {
	_, jwtEncodeSecret, _, _ := test.LoadTestData()
	accessToken := AccessToken{}
	userID := "someuserID"
	err := accessToken.GenerateToken("RS512", jwtEncodeSecret, "somebody@kidsloop.live", &userID, 5 * time.Minute)
	if err != nil {
		t.Errorf("failed to genertate token: %e", err)
	}
	if accessToken.Token == nil {
		t.Errorf("token should be set, but it is nil")
	}
	if accessToken.TokenString == nil {
		t.Errorf("token string should exist, but it is nil")
	}
}

func TestAccessToken_CreateCookie(t *testing.T) {
	_, jwtEncodeSecret, _, _ := test.LoadTestData()
	accessToken := AccessToken{}
	userID := "someuserID"
	err := accessToken.GenerateToken("RS512", jwtEncodeSecret, "somebody@kidsloop.live", &userID, 5 * time.Minute)
	if err != nil {
		t.Errorf("failed to genertate token: %e", err)
	}

	accessCookie := accessToken.CreateCookie("localhost", 5 * time.Minute)
	if accessCookie.Name != "access" {
		t.Errorf("cookie name not correct")
	}
	if accessCookie.Path != "/" {
		t.Errorf("cookie path is incorrect")
	}
	if accessCookie.Value != *accessToken.TokenString {
		t.Errorf("cookie value does not match the token string")
	}
}
