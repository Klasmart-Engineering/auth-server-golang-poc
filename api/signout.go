package api

import "net/http"

func SignOutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: "access",
		Path: "/",
		MaxAge: -1,
	})

	http.SetCookie(w, &http.Cookie{
		Name: "refresh",
		Path: "/refresh",
		MaxAge: -1,
	})

	w.WriteHeader(200)
	return
}