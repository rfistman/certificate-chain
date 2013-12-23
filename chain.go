package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"time"
)

// adapted from http://golang.org/src/pkg/crypto/tls/generate_cert.go
// BUG: serial number

// TODO: this is multi, fix up
var (
	rsaBits      = flag.Int("rsa-bits", 2048, "Size of RSA keys to generate")
	validFor     = flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
	organization = flag.String("organization", "Async Pty. Ltd.", "organization - not the CN?")
	isCA         = flag.Bool("ca", false, "whether this cert should be its own Certificate Authority")
	certType     = flag.String("type", "ca", "ca|client|server")
	dstDir       = flag.String("dst", ".", "destination directory for cert + key")
	parentDir    = flag.String("parent", "", "parent certificate")
)

func main() {
	flag.Parse()

	priv, err := rsa.GenerateKey(rand.Reader, *rsaBits)

	if err != nil {
		log.Fatalf("failed to generate private key: %s", err)
		return
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(*validFor)

	template := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			Organization: []string{*organization},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// DNS names here

	if *isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	parent := &template // default to self-signed

	if len(*parentDir) > 0 {
		if false {
			//type Certificate
			parentCert, err := tls.LoadX509KeyPair(*parentDir+"/cert.pem", *parentDir+"/key.pem")
			if err != nil {
				log.Fatalf("failed to open parent cert", err)
			}
			// is this a shortcut? tls.Cert->x509.Cert (pem->der) should probably just use der throughout
			parent = parentCert.Leaf
			log.Println("parent ", parent)
		} else {
			asn1Cert, err := ioutil.ReadFile(*parentDir + "/cert.cer")
			if err != nil {
				log.Fatal("failed to read parent cert", err)
			}
			parentCert, err := x509.ParseCertificate(asn1Cert)
			parent = parentCert
		}
	}

	switch *certType {
	case "ca":
	case "client":
	case "server":
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, parent, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
		return
	}

	if true {
		err = ioutil.WriteFile(*dstDir+"/cert.cer", derBytes, 0600)
		if err != nil {
			log.Fatalf("failed to open cert.cer for writing: %s", err)
		}

		err = ioutil.WriteFile(*dstDir+"/key.der", x509.MarshalPKCS1PrivateKey(priv), 0600)
		if err != nil {
			log.Fatalf("failed to open key for writing: %s", err)
		}
	} else {
		certOut, err := os.Create(*dstDir + "/cert.pem")
		if err != nil {
			log.Fatalf("failed to open cert.pem for writing: %s", err)
			return
		}
		pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
		certOut.Close()
		log.Print("written cert.pem\n")

		keyOut, err := os.OpenFile(*dstDir+"/key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			log.Print("failed to open key.pem for writing:", err)
			return
		}
		pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
		keyOut.Close()
		log.Print("written key.pem\n")
	}

}
