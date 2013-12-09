package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

// TODO: version number in client CommonName?
// should have read this first
// https://github.com/yunabe/practice/blob/master/golang/tls.go

func helloHandler(w http.ResponseWriter, req *http.Request) {
	fmt.Println("hello")
	commonName := "anonymous"

	peerCerts := req.TLS.PeerCertificates
	if len(peerCerts) > 0 {
		client_cert := peerCerts[0]
		commonName = client_cert.Subject.CommonName
	}
	// NB: shouldn't happen when configured right
	fmt.Fprintf(w, "You are: %s\n", commonName)
}

func main() {
	var err error
	http.HandleFunc("/hello", helloHandler)
	serverCert := "server-cert.pem"
	serverKey := "server-key.pem"

	// with localhost CommonName
	// openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout server-key.pem -out server-cert.pem
	// for iPhone client:
	// openssl x509 -inform pem -outform der -in server-cert.pem -out server-cert.cer

	if false {
		// can hit with (NB: requires common name match)
		// curl --cacert server-cert.pem https://localhost:8081/hello
		// openssl s_client -connect localhost:8081 -tls1 + http requests
		err = http.ListenAndServeTLS(":8081", serverCert, serverKey, nil)
	} else {
		// trying client authentication. Must be signed by CA
		// can hit with:
		// curl --cacert server-cert.pem --cert client-cert.pem --key client-key.pem  https://localhost:8081/hello
		// handy. to squash self sign warning add -CAfile server-cert.pem
		// openssl s_client -connect localhost:8081 -key client-key.pem -cert client-cert.pem -tls1
		clientCertPool := x509.NewCertPool()
		caCertPEM, err := ioutil.ReadFile("FistCA/FistCA-cert.pem")
		if err != nil {
			log.Fatal(err)
		}
		if !clientCertPool.AppendCertsFromPEM(caCertPEM) {
			log.Fatal("no client root certs")
		}

		// clientAuthType := tls.NoClientCert	// don't request client cert
		// clientAuthType := tls.RequestClientCert 	// works with any client cert
		// clientAuthType := tls.RequireAnyClientCert // works with any client
		// clientAuthType := tls.VerifyClientCertIfGiven // allows no cert, gets bad cert for wrong, working for mine.
		clientAuthType := tls.RequireAndVerifyClientCert // no cert or wrong cert = bad certificate, working for mine

		config := &tls.Config{ClientAuth: clientAuthType, ClientCAs: clientCertPool}

		server := &http.Server{Addr: ":8081", Handler: nil, TLSConfig: config}
		err = server.ListenAndServeTLS(serverCert, serverKey)
	}
	if err != nil {
		log.Fatal(err)
	}
}
