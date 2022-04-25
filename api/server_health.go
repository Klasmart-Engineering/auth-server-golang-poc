package api

import "net/http"

func ServerHealth(w http.ResponseWriter, r *http.Request) {
	returnStatus := serverHealthExec(r.Method)
	w.WriteHeader(returnStatus)
	return
}

func serverHealthExec(method string) int {
	switch method {
	case "GET":
		return http.StatusOK
	default:
		return http.StatusMethodNotAllowed
	}
}
