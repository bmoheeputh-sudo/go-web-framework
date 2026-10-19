package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	server, err := newServer(os.Getenv)
	if err != nil {
		return err
	}
	defer server.closeResources()
	if os.Getenv("AUTH_PROVIDER") == "local_dev" {
		log.Print("Local DEV authentication enabled: fixed development identity, no user sessions")
	}
	if os.Getenv("AUTH_PROVIDER") == "oidc" {
		log.Print("OIDC enabled with PostgreSQL sessions")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if server.Shutdown(shutdown) != nil {
			_ = server.Close()
		}
	}()
	log.Printf("Server listening on %s", server.Addr)
	err = server.ListenAndServe()
	stop()
	<-done
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return errors.New("HTTP server failed to start or stopped unexpectedly")
	}
	return nil
}
