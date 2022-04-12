package main

import (
	"github.com/rs/cors"
	"kidsloop-auth-server-2/api"
	"log"
	"net/http"
)

func main() {

	c := cors.New(cors.Options{
		AllowedOrigins: []string{"https://kidskube-dev.kidsloop.live"},
		AllowCredentials: true,
		AllowedHeaders: []string{"Authorization", "Content-Type"},
		MaxAge: 60 * 60 * 24, // One day
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/express/server-health", api.ServerHealth)
	mux.HandleFunc("/transfer", api.TransferHandler)
	mux.HandleFunc("/switch", api.SwitchHandler)
	//mux.HandleFunc("/refresh", api.RefreshHandler)
	//mux.HandleFunc("/signout", api.SignOutHandler)
	handler := c.Handler(mux)
	err := http.ListenAndServe(":8080", handler)
	if err != nil {
		log.Panic("Cannot start server")
	}
}