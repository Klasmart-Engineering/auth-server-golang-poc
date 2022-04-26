package utils

import (
	"fmt"
	"log"
	"net/http"
)

func ServerErrorResponse(statusCode int, w http.ResponseWriter, e error){
	w.WriteHeader(statusCode)
	_, err := fmt.Fprintf(w, e.Error())
	if err != nil {
		log.Printf("Failed to send error response: %v", err.Error())
		log.Printf("Original error: %v", e.Error())
	}
	return
}