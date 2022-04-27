package tokens

import (
	"github.com/lestrrat-go/jwx/jwk"
	"testing"
)

func TestAzureB2CToken_Parse(t *testing.T) {
	sampleRawKeySet := []byte("{\n  \"keys\": [\n    {\"kid\":\"nj5N7G1AaKtgWQtw6SOvxFvSHX1qOfvWz4CHWXaOLjI\",\"use\":\"sig\",\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":\"vD21Zi_raYLmoi8KrezuUOWwOUej1pJIseS7GclgNYXwVxmKCtOQPfnrONqJQMEEZkgtXCjYffAFN2ibCMWtvRjtH2JaBbMtJPdHaoWhNDTrkg705Ad7JqZBw4_IPUi61esluBK3Th1NmGTl2uL0m2ikX0F-wUgOA0lHa0ucZRn6vqn1M09telroSBy6PUSmx4qGmwSl9AsZPRiWJk9KwxTiJCUcgXl6Lty9Z3e4PyhTu2h-iz4L75PJzuOeOjnqakJobViQLiZ2Y6v6qsg6wkyedfiCZFPEAZX_fIiwmpRWJE-lwrWbudIyGB1pKe55h74iUzKN9FuZxvUaCuMgLQ\"}\n  ]\n}")
	sampleKeySet, err := jwk.Parse(sampleRawKeySet)
	if err != nil {
		t.Errorf("unable to parse keyset")
	}
	sampleTokenString := "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Im5qNU43RzFBYUt0Z1dRdHc2U092eEZ2U0hYMXFPZnZXejRDSFdYYU9MakkifQ.eyJpc3MiOiJodHRwczovL2xvZ2luLmxvYWR0ZXN0LmtpZHNsb29wLmxpdmUvOGQ5MjJmZWMtYzFmYy00NzcyLWIzN2UtMThkMmNlNjc5MGRmL3YyLjAvIiwiZXhwIjoxNjUwNjM4MTEyLCJuYmYiOjE2NTA2MzQ1MTIsImF1ZCI6IjkyNjAwMWZlLTc4NTMtNDg1ZC1hMTVlLThjMzZiYjRhY2FlZiIsInN1YiI6IjBiYjcwYzg4LWI2MjQtNDJiOS05MjdjLWEzODQ0ZDFkN2IxMyIsImVtYWlsIjoibWF0dGhldy5yZXZlbGxAb3BlbmNyZWRvLmNvbSIsImlkcCI6IktpZHNMb29wQjJDIiwidGlkIjoiOGQ5MjJmZWMtYzFmYy00NzcyLWIzN2UtMThkMmNlNjc5MGRmIiwibG9jYWxlIjoiZW4iLCJub25jZSI6IjJlNDM0NThlLWU0NWItNGRjZi05NTcwLTcyZWRhZmRkZmQ5OSIsInNjcCI6InRhc2tzLndyaXRlIiwiYXpwIjoiMjRiYzdjNDctOTdjNi00ZjI3LTgzOGUtMDkzYjM5NDhhNWNhIiwidmVyIjoiMS4wIiwiaWF0IjoxNjUwNjM0NTEyfQ.Cn_LcgjcOLwbtTdA-DQkaQet9f1FJhkJPJbzVp-MNayo0knAVdwgYUy5b-UhRyqRcF_28l_Sp_IM00bp1H53zCrUbfYK0hTyB3IQWyGPdnFAsQKTPraXRiBWcEJiqdlH0jDHkEkNEi9X4YI-FKxnIH-TYd1xzKnaMjx2l4jn9j6aBvW_JMZdQcnMVbR47yO_pN4U-rU9xWJQ66wdKWzM4bthxKHfJM9rwXoCDq6zizVZeGd01qqEDtswIY3LlXxFPbT3kb3OUIMwP74Md0MzK80KokczUhNzjq8R_ahP7g1o4mJoSqq9FH040pbmh6JabA1SIRpPxzNdXK9Qsu1ZOA"

	providerToken := AzureB2CToken{
		TokenString: sampleTokenString,
	}
	providerToken.Parse(sampleKeySet)

	if providerToken.Token == nil {
		t.Errorf("token should exist, but it is nil")
	}
}
