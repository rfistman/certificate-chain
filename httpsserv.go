package main

import (
	"log"
	"net/http"
)

func helloHandler(w http.ResponseWriter, req *http.Request) {

}

func main() {
	http.HandleFunc("/hello", helloHandler)
	err := http.ListenAndServeTLS(":8081", "cert.pem", "key.pem", nil)
	if err != nil {
		log.Fatal(err)
	}
}
