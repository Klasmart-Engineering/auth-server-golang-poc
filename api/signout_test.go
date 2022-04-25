package api

import (
	"net/http"
	"testing"
)

func TestSignOutExec(t *testing.T) {
	wantAccessCookie := http.Cookie{
		Name: "access",
		Path: "/",
		MaxAge: -1,
	}

	wantRefreshCookie := http.Cookie{
		Name: "refresh",
		Path: "/refresh",
		MaxAge: -1,
	}

	gotAccessCookie, gotRefreshCookie := signOutExec()

	if gotAccessCookie.String() != wantAccessCookie.String() {
		t.Errorf("Access cookie is not correct. Want: %s, Got: %s", wantAccessCookie.String(), gotAccessCookie.String())
	}
	if gotRefreshCookie.String() != wantRefreshCookie.String() {
		t.Errorf("Refresh cookie is not correct. Want: %s, Got: %s", wantRefreshCookie.String(), gotRefreshCookie.String())
	}
}
