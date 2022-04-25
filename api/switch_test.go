package api

import (
	"fmt"
	"github.com/google/uuid"
	"io"
	"kidsloop-auth-server-2/test"
	"kidsloop-auth-server-2/tokens"
	"kidsloop-auth-server-2/utils"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSwitchExec(t *testing.T) {
	userID := uuid.NewString()
	email := "someone@somewhere.com"
	jwtAlgorithm := "RS512"

	db := new(utils.DummyDBConnector)
	body := io.NopCloser(strings.NewReader(fmt.Sprintf("{\n\"user_id\": \"%s\"\n}", userID)))
	domain := "localhost"
	jwtPublicKey, jwtPrivateKey, _, _ := test.LoadTestData()
	duration := 5 * time.Minute

	prevAccessToken := new(tokens.AccessToken)
	prevAccessToken.GenerateToken(jwtAlgorithm, jwtPrivateKey, email, nil, duration)
	prevAccessCookie := prevAccessToken.CreateCookie("localhost", duration)

	wantStatus := http.StatusOK

	gotStatus, gotAccessCookie, gotRefreshCookie, err := switchExec(
		db,
		body,
		&prevAccessCookie,
		domain,
		jwtAlgorithm,
		jwtPublicKey,
		jwtPrivateKey,
		duration,
		duration,
	)

	if err != nil {
		t.Errorf("error should be nil, got: %e", err)
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