package api

import (
	"github.com/google/uuid"
	"kidsloop-auth-server-2/test"
	"kidsloop-auth-server-2/tokens"
	"net/http"
	"testing"
	"time"
)

func TestRefreshExec(t *testing.T) {
	userID := uuid.NewString()
	email := "someone@somewhere.com"
	domain := "localhost"
	jwtAlgorithm := "RS512"
	jwtPublicKey, jwtPrivateKey, _, _ := test.LoadTestData()
	duration := 5 * time.Minute

	prevAccessToken := new(tokens.AccessToken)
	prevAccessToken.GenerateToken(jwtAlgorithm, jwtPrivateKey, email, &userID, duration)
	prevAccessCookie := prevAccessToken.CreateCookie("localhost", duration)

	prevRefreshToken := new(tokens.RefreshToken)
	prevRefreshToken.GenerateToken(jwtAlgorithm, jwtPrivateKey, uuid.NewString(), email, &userID, duration)
	prevRefreshCookie := prevRefreshToken.CreateCookie(domain, duration)

	wantStatus := http.StatusOK

	gotStatus, gotAccessCookie, gotRefreshCookie, err := refreshExec(
		&prevAccessCookie,
		&prevRefreshCookie,
		jwtAlgorithm,
		jwtPublicKey,
		jwtPrivateKey,
	)
	if err != nil {
		t.Errorf("error should be nil, got: %e", err)
	}
	if gotAccessCookie != nil {
		t.Errorf("access cookie should be nil when access cookie is valid")
	}
	if gotRefreshCookie != nil {
		t.Errorf("refresh cookie should be nil when access cookie is valid")
	}
	if gotStatus != wantStatus {
		t.Errorf("HTTP status is not 200 OK")
	}

	gotStatus, gotAccessCookie, gotRefreshCookie, err = refreshExec(
		nil,
		&prevRefreshCookie,
		jwtAlgorithm,
		jwtPublicKey,
		jwtPrivateKey,
	)
	if err != nil {
		t.Errorf("error should be nil, got: %e", err)
	}
	if gotAccessCookie == nil {
		t.Errorf("access cookie should not be nil when refresh cookie is valid")
	}
	if gotRefreshCookie == nil {
		t.Errorf("refresh cookie should not be nil when refresh cookie is valid")
	}
	if gotStatus != wantStatus {
		t.Errorf("HTTP status is not 200 OK")
	}
}