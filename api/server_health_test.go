package api

import (
	"net/http"
	"testing"
)

func TestServerHealthExec(t *testing.T) {

	// First test: request with GET method, should return (200)
	t.Run("GetRequest", func(t *testing.T) {
		gotResponse := serverHealthExec(http.MethodGet)
		if gotResponse != http.StatusOK {
			t.Errorf("GET response is not 200 OK")
		}
	})

	// Second test: request with POST (or any other method), should return (405)
	t.Run("PostRequest", func(t *testing.T) {
		gotResponse := serverHealthExec(http.MethodPost)
		if gotResponse != http.StatusMethodNotAllowed {
			t.Errorf("Other (POST) response is not 405 MethodNotAllowed")
		}
	})
}
