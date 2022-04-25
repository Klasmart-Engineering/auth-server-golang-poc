package api

import (
	"net/http"
	"testing"
)

func TestServerHealthExec(t *testing.T) {
	wantGetResponse := http.StatusOK
	wantOtherResponse := http.StatusMethodNotAllowed

	gotGetResponse := serverHealthExec(http.MethodGet)
	gotOtherResponse := serverHealthExec(http.MethodPost)

	if gotGetResponse != wantGetResponse {
		t.Errorf("GET response is not correct. Want: %d, Got: %d", wantGetResponse, gotGetResponse)
	}
	if gotOtherResponse != wantOtherResponse {
		t.Errorf("Other (POST) response is not correct. Want %d, Got: %d", wantOtherResponse, gotOtherResponse)
	}
}
