package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func handleProxyRequest(w http.ResponseWriter, req *http.Request) {
	proxyConn, err := net.DialTimeout("tcp", req.Host, 5*time.Second)
	if err != nil {
		fmt.Println(err)
		http.Error(w, http.StatusText(http.StatusRequestTimeout), http.StatusRequestTimeout)
		return
	}

	w.WriteHeader(http.StatusOK)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		fmt.Println("Connection hijacking not supported")
		http.Error(w, http.StatusText(http.StatusExpectationFailed), http.StatusExpectationFailed)
		return
	}

	reqConn, _, err := hijacker.Hijack()
	if err != nil {
		fmt.Println(err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	go transfer(proxyConn, reqConn)
	go transfer(reqConn, proxyConn)
}

func handleApiRequest(w http.ResponseWriter) {
	resp, err := http.Get("https://www.bing.com")
	if err != nil {
		fmt.Println(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}
