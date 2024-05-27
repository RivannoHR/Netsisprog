package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"main/tools"
	"math/big"
	"time"
)

func main() {
	serverAddr := "google.com:443"

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tools.HandleIt(err)

	cert, err := createSelfSignedCert(privateKey)
	tools.HandleIt(err)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{{Certificate: [][]byte{cert.Raw}}},
		ClientAuth:         tls.NoClientCert,
	}

	conn, err := tls.Dial("tcp", serverAddr, tlsConfig)
	tools.HandleIt(err)
	defer conn.Close()

	state := conn.ConnectionState()

	tlsVersion := state.Version
	cipherSuite := state.CipherSuite
	issuer := state.PeerCertificates[0].Issuer.Organization

	fmt.Printf("Connected to Google using TLSv%d\n", tlsVersion)
	fmt.Print("Cipher Suite: ")
	fmt.Println(cipherSuite)
	fmt.Printf("Issuer: %s\n", issuer)

	fmt.Println("Connection closed.")
}

func createSelfSignedCert(privateKey *ecdsa.PrivateKey) (*x509.Certificate, error) {
	subject := pkix.Name{
		CommonName:   "Skibidi",
		Organization: []string{"Sigma Baby gronk Inc."},
	}

	now := time.Now()
	validFor := time.Hour * 24
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tools.HandleIt(err)
	cert := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             now,
		NotAfter:              now.Add(validFor),
		PublicKey:             privateKey.Public(),
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		Issuer:                subject,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, privateKey.Public(), privateKey)
	tools.HandleIt(err)

	return x509.ParseCertificate(derBytes)
}
