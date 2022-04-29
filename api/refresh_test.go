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

	expiredAccessToken := new(tokens.AccessToken)
	expiredAccessToken.GenerateToken(jwtAlgorithm, jwtPrivateKey, email, &userID, 0)
	expiredAccessCookie := expiredAccessToken.CreateCookie(domain, 0)

	prevRefreshToken := new(tokens.RefreshToken)
	prevRefreshToken.GenerateToken(jwtAlgorithm, jwtPrivateKey, uuid.NewString(), email, &userID, duration)
	prevRefreshCookie := prevRefreshToken.CreateCookie(domain, duration)

	expiredRefreshToken := new(tokens.RefreshToken)
	expiredRefreshToken.GenerateToken(jwtAlgorithm, jwtPrivateKey, uuid.NewString(), email, &userID, 0)
	expiredRefreshCookie := expiredRefreshToken.CreateCookie(domain, 0)

	// First test: access token is valid, should return (200, nil, nil, nil)
	t.Run("AccessTokenStillValid", func(t *testing.T) {
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
		if gotStatus != http.StatusOK {
			t.Errorf("HTTP status is not 200 OK")
		}
	})

	// Second test: access token is nil, should return (200, accessCookie, refreshCookie, nil)
	t.Run("AccessTokenMissing", func(t *testing.T) {
		gotStatus, gotAccessCookie, gotRefreshCookie, err := refreshExec(
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
		if gotStatus != http.StatusOK {
			t.Errorf("HTTP status is not 200 OK")
		}
	})

	// Third test: access token is expired (not valid), should return (200, accessCookie, refreshCookie, nil)
	t.Run("AccessTokenExpired", func(t *testing.T) {
		gotStatus, gotAccessCookie, gotRefreshCookie, err := refreshExec(
			&expiredAccessCookie,
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
		if gotStatus != http.StatusOK {
			t.Errorf("HTTP status is not 200 OK")
		}
	})

	// Forth test: access token and refresh token are both expired (not valid), should return (401, nil, nil, nil)
	t.Run("BothTokensExpired", func(t *testing.T) {
		gotStatus, gotAccessCookie, gotRefreshCookie, err := refreshExec(
			&expiredAccessCookie,
			&expiredRefreshCookie,
			jwtAlgorithm,
			jwtPublicKey,
			jwtPrivateKey,
		)
		if err != nil {
			t.Errorf("error should be nil, got: %e", err)
		}
		if gotAccessCookie != nil {
			t.Errorf("access cookie should be nil when unauthorized")
		}
		if gotRefreshCookie != nil {
			t.Errorf("refresh cookie should be nil when unauthorized")
		}
		if gotStatus != http.StatusUnauthorized {
			t.Errorf("HTTP status is not 401 Unauthorized")
		}
	})
}
