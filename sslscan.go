/*Package sslyze parses SSLScan XML data into a similary formed struct.*/

package sslscan

import (
	"encoding/xml"
)

type SSLScanRun struct {
	Title   string    `xml:"title,attr"`
	Version string    `xml:"version,attr"`
	Web     string    `xml:"web,attr"`
	SSLTest []SSLTest `xml:"ssltest"`
}

type SSLTest struct {
	Host          string        `xml:"host,attr"`
	Port          string        `xml:"port,attr"`
	Renegotiation Renegotiation `xml:"renegotiation"`
	Compression   Compression   `xml:"compression"`
	Heartbleed    []Heartbleed  `xml:"heartbleed"`
	Cipher        []Cipher      `xml:"cipher"`
	DefaultCipher Cipher        `xml:"defaultcipher"`
	Certificate   Certificate   `xml:"certificate"`
}

type Renegotiation struct {
	Supported bool `xml:"supported,attr"`
	Secure    bool `xml:"secure,attr"`
}

type Compression struct {
	Supported bool `xml:"supported,attr"`
}

type Heartbleed struct {
	SSLVersion string `xml:"sslversion,attr"`
	Vulnerable bool   `xml:"vulnerable,attr"`
}

type Cipher struct {
	Status     string `xml:"status,attr"`
	SSLVersion string `xml:"sslversion,attr"`
	Bits       int    `xml:"bits,attr"`
	Cipher     string `xml:"cipher,attr"`
}

type Certificate struct {
	SignatureAlgorithm string    `xml:"signature-algorithm"`
	PublicKey          PublicKey `xml:"pk"`
	Subject            string    `xml:"subject"`
	AltNames           string    `xml:"altnames"`
	Issuer             string    `xml:"issuer"`
	SelfSigned         bool      `xml:"self-signed"`
}

type PublicKey struct {
	Error bool   `xml:"error,attr"`
	Type  string `xml:"type,attr"`
	Bits  int    `xml:"bits,attr"`
}

// Parse takes a byte array of sslscan xml data and unmarshals it into an
// SSLScanRun struct. All elements are returned as strings, it is up to the caller
// to check and cast them to the proper type.
func Parse(content []byte) (*SSLScanRun, error) {
	r := &SSLScanRun{}
	err := xml.Unmarshal(content, r)
	if err != nil {
		return r, err
	}
	return r, nil
}
