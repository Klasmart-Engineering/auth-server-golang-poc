package api

import "net/http"

// SignOutHandler - Wrapper function called from the main HTTP Server Mutex
func SignOutHandler(w http.ResponseWriter, r *http.Request) {
	accessCookie, refreshCookie := signOutExec()
	http.SetCookie(w, &accessCookie)
	http.SetCookie(w, &refreshCookie)

	w.WriteHeader(200)
	return
}

// signOutExec - Internal function to perform sign out
// This function has been abstracted to be able to test it in isolation
func signOutExec() (http.Cookie, http.Cookie) {
	accessCookie := http.Cookie{
		Name:   "access",
		Path:   "/",
		MaxAge: -1,
	}

	refreshCookie := http.Cookie{
		Name:   "refresh",
		Path:   "/refresh",
		MaxAge: -1,
	}

	return accessCookie, refreshCookie
}
