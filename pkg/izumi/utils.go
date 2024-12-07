package izumi

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	mrand "math/rand"
	"strings"
	"time"
)

// Helper function to generate a temporary certificate with container identity
func GenerateSelfSignedCert(caCert *x509.Certificate, caKey *rsa.PrivateKey, containerID string) (tls.Certificate, error) {
	// Create a new private key for the certificate
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate private key: %v", err)
	}

	// Create an ObjectIdentifier for our custom container ID extension
	containerIDOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12345, 1, 1} // Use your organization's OID

	// Create the extension containing the container ID
	containerIDExtension, err := asn1.Marshal(containerID)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to marshal container ID: %v", err)
	}

	// Create a certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("container-%s.izumi.local", containerID),
			Organization: []string{"Izumi Corp"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:                  false,
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       containerIDOID,
				Critical: true,
				Value:    containerIDExtension,
			},
		},
		DNSNames: []string{
			fmt.Sprintf("container-%s.izumi.local", containerID),
		},
	}

	// Sign the certificate with the CA's private key
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &privKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate: %v", err)
	}

	// Encode the certificate and private key to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// Helper function to extract container ID from certificate
func ExtractContainerID(cert *x509.Certificate) (string, error) {
	// Define the OID for our container ID extension
	containerIDOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 12345, 1, 1}

	// Look for our custom extension
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(containerIDOID) {
			var containerID string
			_, err := asn1.Unmarshal(ext.Value, &containerID)
			if err != nil {
				return "", fmt.Errorf("failed to unmarshal container ID: %v", err)
			}
			return containerID, nil
		}
	}

	// Fallback: try to extract from Common Name if extension not found
	// Expected format: "container-{id}.izumi.local"
	prefix := "container-"
	suffix := ".izumi.local"
	cn := cert.Subject.CommonName
	if strings.HasPrefix(cn, prefix) && strings.HasSuffix(cn, suffix) {
		containerID := cn[len(prefix) : len(cn)-len(suffix)]
		if containerID != "" {
			return containerID, nil
		}
	}

	return "", fmt.Errorf("container ID not found in certificate")
}

// Helper function to validate container ID in certificate
func ValidateContainerCert(cert *x509.Certificate, expectedContainerID string) error {
	containerID, err := ExtractContainerID(cert)
	if err != nil {
		return fmt.Errorf("failed to extract container ID: %v", err)
	}

	if containerID != expectedContainerID {
		return fmt.Errorf("certificate container ID (%s) does not match expected ID (%s)",
			containerID, expectedContainerID)
	}

	return nil
}

func LoadCACertAndKey(caCertPEM, caKeyPEM []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil || caCertBlock.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("failed to decode CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA key PEM")
	}

	var caKey *rsa.PrivateKey
	switch caKeyBlock.Type {
	case "RSA PRIVATE KEY":
		caKey, err = x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse PKCS#1 private key: %v", err)
		}
	case "PRIVATE KEY":
		keyInterface, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse PKCS#8 private key: %v", err)
		}
		var ok bool
		caKey, ok = keyInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("not an RSA private key")
		}
	default:
		return nil, nil, fmt.Errorf("unsupported key type: %s", caKeyBlock.Type)
	}

	return caCert, caKey, nil
}

func GenerateRandomContainerID(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789.-_"
	seededRand := mrand.New(mrand.NewSource(time.Now().UnixNano()))

	result := make([]byte, length)
	for i := range result {
		result[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(result)
}
