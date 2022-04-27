package api

import (
	"kidsloop-auth-server-2/test"
	"net/http"
	"testing"
	"time"
)

func TestTransferExec(t *testing.T) {
	email := "someone@somewhere.com"
	domain := "localhost"
	jwtAlgorithm := "RS512"
	_, jwtPrivateKey, _, _ := test.LoadTestData()
	duration := 5 * time.Minute

	wantStatus := http.StatusOK

	gotStatus, gotAccessCookie, gotRefreshCookie, err := transferExec(
		email,
		domain,
		jwtAlgorithm,
		jwtPrivateKey,
		duration,
		duration,
	)

	if err != nil {
		t.Errorf("error should not be nil, got: %e", err)
	}
	if gotAccessCookie == nil {
		t.Errorf("access cookie should not be nil")
	}
	if gotRefreshCookie == nil {
		t.Errorf("refresh cookie should not be nil")
	}
	if gotStatus != wantStatus {
		t.Errorf("HTTP status is not 200 OK")
	}
}
