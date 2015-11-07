/*Package sslyze parses SSLScan XML data into a similary formed struct.*/

package sslscan

import (
	"encoding/xml"
)

// SSLScanData contains all the data form a single sslscan job.
type SSLScanData struct {
	Title   string    `xml:"title,attr"`
	Version string    `xml:"version,attr"`
	Web     string    `xml:"web,attr"`
	SSLTest []SSLTest `xml:"ssltest"`
}

// SSLTest contains sslscan results.
type SSLTest struct {
	Host          string        `xml:"host,attr"`
	Port          int           `xml:"port,attr"`
	Renegotiation Renegotiation `xml:"renegotiation"`
	Compression   Compression   `xml:"compression"`
	Heartbleed    []Heartbleed  `xml:"heartbleed"`
	Cipher        []Cipher      `xml:"cipher"`
	DefaultCipher Cipher        `xml:"defaultcipher"`
	Certificate   Certificate   `xml:"certificate"`
}

// Renegotation contains the renegotation results.
type Renegotiation struct {
	Supported bool `xml:"supported,attr"`
	Secure    bool `xml:"secure,attr"`
}

// Compression contains the compression results.
type Compression struct {
	Supported bool `xml:"supported,attr"`
}

// Heatbleed contains the heartbleed results.
type Heartbleed struct {
	SSLVersion string `xml:"sslversion,attr"`
	Vulnerable bool   `xml:"vulnerable,attr"`
}

// Cipher contains the support cipher suites..
type Cipher struct {
	Status     string `xml:"status,attr"`
	SSLVersion string `xml:"sslversion,attr"`
	Bits       int    `xml:"bits,attr"`
	Cipher     string `xml:"cipher,attr"`
	Curve      string `xml:"curve,attr"`
	EcdheBits  int    `xml:"ecdhebits,attr"`
}

// Certificate contains the certificate parameters.
type Certificate struct {
	SignatureAlgorithm string    `xml:"signature-algorithm"`
	PublicKey          PublicKey `xml:"pk"`
	Subject            string    `xml:"subject"`
	AltNames           string    `xml:"altnames"`
	Issuer             string    `xml:"issuer"`
	SelfSigned         bool      `xml:"self-signed"`
}

// PublicKey contains the public key parameters.
type PublicKey struct {
	Error bool   `xml:"error,attr"`
	Type  string `xml:"type,attr"`
	Bits  int    `xml:"bits,attr"`
}

// Parse takes a byte array of sslscan xml data and unmarshals it into an
// SSLScanRun struct. All elements are returned as strings, it is up to the caller
// to check and cast them to the proper type.
func Parse(content []byte) (*SSLScanData, error) {
	r := &SSLScanData{}
	err := xml.Unmarshal(content, r)
	if err != nil {
		return r, err
	}
	return r, nil
}
