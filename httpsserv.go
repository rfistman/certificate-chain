package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func helloHandler(w http.ResponseWriter, req *http.Request) {
	fmt.Println("hello")
}

func main() {
	var err error
	if false {
		http.HandleFunc("/hello", helloHandler)
		// openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout key.pem -out cert.pem
		err = http.ListenAndServeTLS(":8081", "cert.pem", "key.pem", nil)
	} else {
		// trying client authentication
		certPool := x509.NewCertPool()
		clientPem, err := ioutil.ReadFile("cert2.pem")
		if err != nil {
			log.Fatal(err)
		}
		if !certPool.AppendCertsFromPEM(clientPem) {
			log.Fatal("no client certs")
		}
		config := &tls.Config{Certificates: nil, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: certPool}

		server := &http.Server{Addr: ":8081", Handler: nil, TLSConfig: config}
		err = server.ListenAndServeTLS("cert.pem", "key.pem")
	}
	if err != nil {
		log.Fatal(err)
	}
}
