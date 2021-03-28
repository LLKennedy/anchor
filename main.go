package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/LLKennedy/anchor/generate"
	"github.com/spf13/cobra"
)

var commands = []string{
	"init",
	"sign",
}

func main() {
	cmd := &cobra.Command{
		Use: fmt.Sprintf("anchor %s", strings.Join(commands, " | ")),
		RunE: func(cmd *cobra.Command, args []string) error {
			key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			if err != nil {
				return err
			}
			cert, err := generate.Root(&x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "TestRoot",
				},
			}, key, time.Now(), time.Now().Add(24*time.Hour))
			if err != nil {
				return err
			}
			certFile, err := os.Create("root.crt")
			if err != nil {
				return err
			}
			defer certFile.Close()
			err = pem.Encode(certFile, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			})
			if err != nil {
				return err
			}
			keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				return err
			}
			keyFile, err := os.Create("root.key")
			if err != nil {
				return err
			}
			defer keyFile.Close()
			err = pem.Encode(keyFile, &pem.Block{
				Type:  "ECDSA PRIVATE KEY",
				Bytes: keyBytes,
			})
			return err
		},
	}
	err := cmd.RunE(cmd, os.Args)
	if err != nil {
		log.Fatalln(err)
	}
}
