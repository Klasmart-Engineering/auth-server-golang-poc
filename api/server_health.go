package api

import "net/http"

// ServerHealth - Wrapper function called from the main HTTP Server Mutex
func ServerHealth(w http.ResponseWriter, r *http.Request) {
	returnStatus := serverHealthExec(r.Method)
	w.WriteHeader(returnStatus)
	return
}

// serverHealthExec - Internal function to perform server health
// This function has been abstracted to be able to test it in isolation
// TODO: Server Health can be more sophisticated e.g. checking connectivity to external services
func serverHealthExec(method string) int {
	switch method {
	case "GET":
		return http.StatusOK
	default:
		return http.StatusMethodNotAllowed
	}
}
