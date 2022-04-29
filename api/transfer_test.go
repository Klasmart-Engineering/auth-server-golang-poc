package api

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/lestrrat-go/jwx/jwk"
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

func TestValidateBearerToken(t *testing.T) {
	_, privateKey, fakeToken, _ := test.LoadTestData()
	fakeToken.Header["kid"] = "fake_kid"
	fakeTokenString, err := fakeToken.SignedString(privateKey)
	if err != nil {
		t.Errorf("failed to generate fake provider token")
	}

	pemBlock, _ := pem.Decode([]byte(test.PublicKey))
	rawKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		t.Errorf("failed to parse public key")
	}
	key, err := jwk.New(rawKey)
	if err != nil {
		t.Errorf("failed to create jwk key")
	}
	key.Set("kid", "fake_kid")
	keySet := jwk.NewSet()
	keySet.Add(key)

	gotEmail, gotValid, err := validateBearerToken(fakeTokenString, &keySet)
	if err != nil {
		t.Errorf("failed to validate bearer token: %s", err.Error())
	}

	if gotEmail == nil {
		t.Errorf("email should not be nil")
	}
	if !gotValid {
		t.Errorf("token should be valid")
	}



}
