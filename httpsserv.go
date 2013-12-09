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
		// trying client authentication, with CommonName client
		// openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout client-key.pem -out client-cert.pem
		// can hit with:
		// curl --cacert server-cert.pem --cert client-cert.pem --key client-key.pem  https://localhost:8081/hello
		// p12 export:
		// openssl pkcs12 -export -out client.p12 -inkey client-key.pem -in client-cert.pem
		certPool := x509.NewCertPool()
		clientPem, err := ioutil.ReadFile("client-cert.pem")
		if err != nil {
			log.Fatal(err)
		}
		if !certPool.AppendCertsFromPEM(clientPem) {
			log.Fatal("no client certs")
		}

		// clientAuthType := tls.NoClientCert	// don't request client cert
		// clientAuthType := tls.RequestClientCert 	// works with any client cert
		// clientAuthType := tls.RequireAnyClientCert // works with any client
		// clientAuthType := tls.VerifyClientCertIfGiven // allows no cert, gets bad cert for wrong, handshake fail for mine.
		clientAuthType := tls.RequireAndVerifyClientCert // no cert or wrong cert = bad certificate, handshake fail for mine

		// not working with
		// openssl s_client -connect localhost:8081 -key client-key.pem -cert client-cert.pem -tls1

		// try creating RootCAs with client auth?
		// why is certPool not working?
		// do I need to be own CA?
		// I guess I can check common name, but that's not right
		// config.InsecureSkipVerify: true is only for outgoing
		config := &tls.Config{ /* Certificates: nil , InsecureSkipVerify: true, */ ClientAuth: clientAuthType, ClientCAs: certPool}

		server := &http.Server{Addr: ":8081", Handler: nil, TLSConfig: config}
		err = server.ListenAndServeTLS(serverCert, serverKey)
	}
	if err != nil {
		log.Fatal(err)
	}
}
