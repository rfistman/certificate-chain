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

// rand.Reader().ReadInt64?

// adapted from http://golang.org/src/pkg/crypto/tls/generate_cert.go
// BUG: serial number
// TODO:
// DNSNames:       []string{"test.example.com"},
// EmailAddresses: []string{"gopher@golang.org"},
// TODO: this is multi, fix up
var (
	rsaBits      = flag.Int("rsa-bits", 2048, "Size of RSA keys to generate")
	validFor     = flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
	organization = flag.String("organization", "Async Pty. Ltd.", "organization - not the CN?")
	certType     = flag.String("type", "ca", "ca|client|server")
	dstDir       = flag.String("dst", ".", "destination directory for cert + key")
	parentDir    = flag.String("parent", "", "parent certificate")
	commonName   = flag.String("cn", "", "Common Name")
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
			Country:      []string{"AU"},
			Province:     []string{"NSW"},
			Locality:     []string{"Sydney"},
			CommonName:   *commonName,
			Organization: []string{*organization},
			//OrganizationalUnit: []string{"Async Certification Authority"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		//ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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
		// AGL says whole chain must either have no key usage specified or
		// client auth all the way or have extended any. Due to bug in for loop,
		// need to build go from source after 10 dec 2013.
		// https://groups.google.com/forum/#!topic/golang-nuts/753fOH9mQz0
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	case "client":
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case "server":
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
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
