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
	domain := "localhost"
	jwtPublicKey, jwtPrivateKey, _, _ := test.LoadTestData()
	duration := 5 * time.Minute

	prevAccessToken := new(tokens.AccessToken)
	prevAccessToken.GenerateToken(jwtAlgorithm, jwtPrivateKey, email, nil, duration)
	prevAccessCookie := prevAccessToken.CreateCookie("localhost", duration)

	expiredAccessToken := new(tokens.AccessToken)
	expiredAccessToken.GenerateToken(jwtAlgorithm, jwtPrivateKey, email, nil, 0)
	expiredAccessCookie := expiredAccessToken.CreateCookie(domain, 0)


	// First test: tokens and POST data are all valid, should return (200, accessCookie, refreshCookie, nil)
	t.Run("TokensAndUserDataValid", func(t *testing.T) {
		validBody := io.NopCloser(strings.NewReader(fmt.Sprintf("{\n\"user_id\": \"%s\"\n}", userID)))
		gotStatus, gotAccessCookie, gotRefreshCookie, err := switchExec(
			db,
			validBody,
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
		if gotStatus != http.StatusOK {
			t.Errorf("HTTP status is not 200 OK")
		}
	})

	// Second test: Data in the POST body is invalid JSON, should return (400, nil, nil, error)
	t.Run("PostDataInvalidJSON", func(t *testing.T) {
		invalidJSONBody := io.NopCloser(strings.NewReader("this is not JSON"))
		gotStatus, gotAccessCookie, gotRefreshCookie, err := switchExec(
			db,
			invalidJSONBody,
			&prevAccessCookie,
			domain,
			jwtAlgorithm,
			jwtPublicKey,
			jwtPrivateKey,
			duration,
			duration,
		)

		if err == nil {
			t.Errorf("error should not be nil")
		}
		if gotAccessCookie != nil {
			t.Errorf("access cookie should be nil")
		}
		if gotRefreshCookie != nil {
			t.Errorf("refresh cookie should be nil")
		}
		if gotStatus != http.StatusBadRequest {
			t.Errorf("HTTP status is not 400 BadRequest")
		}
	})

	// Third test: User ID is not valid (for the test DummyDBConnector returns true if it gets a UUID, false if not), should return (401, nil, nil, nil)
	t.Run("UserIDInvalid", func(t *testing.T) {
		invalidUserBody := io.NopCloser(strings.NewReader("{\n\"user_id\": \"not_a_user\"\n}"))
		gotStatus, gotAccessCookie, gotRefreshCookie, err := switchExec(
			db,
			invalidUserBody,
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
		if gotAccessCookie != nil {
			t.Errorf("access cookie should be nil")
		}
		if gotRefreshCookie != nil {
			t.Errorf("refresh cookie should be nil")
		}
		if gotStatus != http.StatusUnauthorized {
			t.Errorf("HTTP status is not 401 Unauthorized")
		}
	})

	// Forth test: Previous Access Token is expired, should return (401, nil, nil, nil)
	t.Run("PrevAccessTokenExpired", func(t *testing.T) {
		validBody := io.NopCloser(strings.NewReader(fmt.Sprintf("{\n\"user_id\": \"%s\"\n}", userID)))
		gotStatus, gotAccessCookie, gotRefreshCookie, err := switchExec(
			db,
			validBody,
			&expiredAccessCookie,
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
		if gotAccessCookie != nil {
			t.Errorf("access cookie should be nil")
		}
		if gotRefreshCookie != nil {
			t.Errorf("refresh cookie should be nil")
		}
		if gotStatus != http.StatusUnauthorized {
			t.Errorf("HTTP status is not 401 Unauthorized")
		}
	})
}
