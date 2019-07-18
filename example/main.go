package main

import (
	"log"
	"net/http"

	"github.com/goroute/cors"
	"github.com/goroute/route"
)

func main() {
	mux := route.NewServeMux()

	mux.Use(cors.New())

	log.Fatal(http.ListenAndServe(":9000", mux))
}
