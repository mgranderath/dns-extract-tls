package main

import (
	"crypto/md5"
	"crypto/x509"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"extract-tls/db"
	"fmt"
	"log"
	"os"
	"strconv"
)

type ParsedCerts struct {
	Version int

	CommonName string
	Organization []string
	DNSNames []string

	AuthorityID []uint8
	SubjectID []uint8
	Size int

	PublicKeyAlgorithm string
	SignatureAlgorithm string

	CertHash string
}

func checkError(message string, err error) {
	if err != nil {
		log.Fatal(message, err)
	}
}

func main() {
	certs := db.GetCerts()

	file, err := os.Create("result.csv")
	checkError("Cannot create file", err)
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	for _, certRecord := range certs {
		cert, err := x509.ParseCertificate(certRecord.Raw)
		if err != nil {
			log.Fatal(err)
		}
		commonName := cert.Subject.CommonName
		organization := cert.Subject.Organization
		dnsNames := cert.DNSNames

		hash := md5.Sum(cert.Raw)

		parsedCert := ParsedCerts{
			Version: cert.Version,

			CommonName:   commonName,
			Organization: organization,
			DNSNames: dnsNames,
			AuthorityID: cert.AuthorityKeyId,
			SubjectID: cert.SubjectKeyId,
			Size: len(certRecord.Raw),

			PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
			SignatureAlgorithm: cert.SignatureAlgorithm.String(),

			CertHash: hex.EncodeToString(hash[:]),
		}
		b, err := json.Marshal(parsedCert)
		if err != nil {
			fmt.Println(err)
			return
		}

		err = writer.Write([]string{certRecord.IP, certRecord.Protocol, strconv.Itoa(certRecord.Port), string(b)})
		checkError("could not write to file", err)
	}
}