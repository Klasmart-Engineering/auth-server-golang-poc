package utils

import (
	"fmt"
	"log"
	"net/http"
)

// ServerErrorResponse - This is a helper function to send a response when an error occurs
// TODO: This currently sends actual error output to the client. It should probably only print to logs instead
func ServerErrorResponse(statusCode int, w http.ResponseWriter, e error) {
	w.WriteHeader(statusCode)
	_, err := fmt.Fprintf(w, e.Error())
	if err != nil {
		log.Printf("Failed to send error response: %v", err.Error())
		log.Printf("Original error: %v", e.Error())
	}
	return
}
