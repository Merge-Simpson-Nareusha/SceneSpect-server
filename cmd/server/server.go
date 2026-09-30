package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"
)

// # HTTP 서버 구성 기능
func newHTTPServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

// # HTTP 서버 실행 및 종료 기능
func serve(server *http.Server, stop context.CancelFunc) {
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("server: %v", err)
		stop()
	}
}
