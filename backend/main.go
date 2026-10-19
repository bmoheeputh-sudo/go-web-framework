package main

import (
    "encoding/json"
    "log"
    "net/http"
)

func main() {
    mux := http.NewServeMux()

    mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]string{
            "status": "ok",
            "service": "go-web-framework",
        })
    })

    log.Println("Server running at http://localhost:8080")

    if err := http.ListenAndServe("127.0.0.1:8080", mux); err != nil {
        log.Fatal(err)
    }
}
