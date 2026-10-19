package main

import (
	"log"
	"os"
)

func main() {
	server, err := newServer(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	if os.Getenv("AUTH_PROVIDER") == "local_dev" {
		log.Print("Local DEV authentication enabled: fixed development identity, no user sessions")
	}
	log.Printf("Server listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
