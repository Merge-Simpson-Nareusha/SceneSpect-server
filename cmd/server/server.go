package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"
)

// newHTTPServer는 요청 처리 시간을 제한한 서버를 만듭니다.
// 헤더와 본문을 무기한 기다리는 연결이 서버 자원을 점유하지 않도록 각 단계에 상한을 둡니다.
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

// serve는 별도 goroutine에서 HTTP 요청을 받고, 정상 종료 이외의 실패를 로그에 남깁니다.
// 시작 실패 시 stop을 호출해 main의 대기와 의존성 정리가 진행되도록 합니다.
func serve(server *http.Server, stop context.CancelFunc) {
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("server: %v", err)
		stop()
	}
}
