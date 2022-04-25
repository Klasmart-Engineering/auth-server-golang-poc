package api

import "net/http"

func SignOutHandler(w http.ResponseWriter, r *http.Request) {
	accessCookie, refreshCookie := signOutExec()
	http.SetCookie(w, &accessCookie)
	http.SetCookie(w, &refreshCookie)

	w.WriteHeader(200)
	return
}

func signOutExec() (http.Cookie, http.Cookie) {
	accessCookie := http.Cookie{
		Name: "access",
		Path: "/",
		MaxAge: -1,
	}

	refreshCookie := http.Cookie{
		Name: "refresh",
		Path: "/refresh",
		MaxAge: -1,
	}

	return accessCookie, refreshCookie
}