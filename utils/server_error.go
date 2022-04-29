package utils

import (
	"log"
	"net/http"
)

// ServerErrorResponse - This is a helper function to send a response when an error occurs
func ServerErrorResponse(statusCode int, w http.ResponseWriter, err error) {
	w.WriteHeader(statusCode)
	log.Printf("Error: %e", err)
	return
}
