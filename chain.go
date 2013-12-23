package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"io/ioutil"
	"log"
	"math/big"
	"time"
)

// adapted from http://golang.org/src/pkg/crypto/tls/generate_cert.go
// BUG: serial number

// TODO: this is multi, fix up
var (
	rsaBits      = flag.Int("rsa-bits", 2048, "Size of RSA keys to generate")
	validFor     = flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
	organization = flag.String("organization", "Async Pty. Ltd.", "organization - not the CN?")
	certType     = flag.String("type", "ca", "ca|client|server")
	dstDir       = flag.String("dst", ".", "destination directory for cert + key")
	parentDir    = flag.String("parent", "", "parent certificate")
)

func main() {
	flag.Parse()

	privateKey, err := rsa.GenerateKey(rand.Reader, *rsaBits)

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

	// self signed case. too lazy to write down types
	parent := &template // default to self-signed
	signingKey := &privateKey

	if len(*parentDir) > 0 {
		asn1Cert, err := ioutil.ReadFile(*parentDir + "/cert.cer")
		if err != nil {
			log.Fatal("failed to read parent cert", err)
		}
		parentCert, err := x509.ParseCertificate(asn1Cert)

		asn1Key, err := ioutil.ReadFile(*parentDir + "/key.der")
		if err != nil {
			log.Fatal("failed to read private key", err)
		}

		parentKey, err := x509.ParsePKCS1PrivateKey(asn1Key)
		if err != nil {
			log.Fatal("failed to parse private key", err)
		}

		parent = parentCert
		signingKey = &parentKey
	}

	switch *certType {
	case "ca":
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	case "client":
	case "server":
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, parent, &privateKey.PublicKey, *signingKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
		return
	}

	err = ioutil.WriteFile(*dstDir+"/cert.cer", derBytes, 0600)
	if err != nil {
		log.Fatalf("failed to open cert.cer for writing: %s", err)
	}

	err = ioutil.WriteFile(*dstDir+"/key.der", x509.MarshalPKCS1PrivateKey(privateKey), 0600)
	if err != nil {
		log.Fatalf("failed to open key for writing: %s", err)
	}

}
