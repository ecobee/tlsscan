package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
)

// Look up TLS version names
var tlsNumtoName = map[uint16]string{
	0x300: "SSLv3",
	0x301: "TLSv1_0",
	0x302: "TLSv1_1",
	0x303: "TLSv1_2",
	0x304: "TLSv1_3",
}

type jsonOutput struct {
	CipherSuites []string `json:"ciphersuites"`
	TLSVersions  []string `json:"tlsversion"`
}

// makeTLSConnection will establish a TLS connection and return the uint16 representing the established ciphersuite and
// a bool representing if the handshake was completed successfully
func makeTLSConnection(cipherSuites []uint16, tlsMin uint16, tlsMax uint16, host string) (uint16, bool) {
	// TLS configuration used by the client.  It is deliberately terrible ;)
	var myTLSConfig = tls.Config{
		MinVersion:         tlsMin,
		MaxVersion:         tlsMax,
		InsecureSkipVerify: false, // Yeah, checking certs would be nice
		//VerifyPeerCertificate  //  <-  can do cert pinning
		SessionTicketsDisabled:   false,
		CipherSuites:             cipherSuites,
		PreferServerCipherSuites: true, // This lets us enumerate the servers preferred order
	}

	// use tls.Dial to establish a connection to host using tlsConfig as configuration
	conn, err := tls.Dial("tcp", host, &myTLSConfig)
	if err != nil {
		//fmt.Printf("There seems to be a problem :(\n")
		return 0x0000, false
	}
	// Close the connection when we're done
	defer conn.Close()

	// Get details of connection state
	state := conn.ConnectionState()
	//fmt.Printf("State: %v\n", state)

	// Return the ciphersuite from the state
	return state.CipherSuite, true
}

func main() {
	// Check commandline config options
	var host = flag.String("host", "127.0.0.1:443", "host to test, format: hostname:port")

	// Mmmm variables
	var preferredSuites []uint16
	var preferredSuitesHuman []string
	var cipherSuites []uint16
	var selectedSuite uint16
	var tlsSupport []string
	var tlsMax uint16 = 0x304 // TLS 1.3... we need to support, I just need a sane upper bound
	var tlsMin uint16 = 0x300 // SSLv3 ... not even attempting SSLv2, it's super rare and horrible

	// Parse commandline options
	flag.Parse()

	handshakeSuccess := true

	// List of ciphersuites to test.  As suites are accepted by the server they will be removed from the list and
	// the connection retried in order to enumerate the next ciphersuite which the server permits.  This adds
	// all the suites
	for i := range cipherSuiteList {
		cipherSuites = append(cipherSuites, i)
	}

	// Supported CipherSuite Test (using full spectrum TLS versions)
	for handshakeSuccess == true {
		// Make a TLS connection and add the negotiated protocol to the preferredSuites
		selectedSuite, handshakeSuccess = makeTLSConnection(cipherSuites, tlsMin, tlsMax, *host)
		if handshakeSuccess == true {
			preferredSuites = append(preferredSuites, selectedSuite)
			preferredSuitesHuman = append(preferredSuitesHuman, cipherSuiteList[selectedSuite])
		}

		// Change the selectedSuite to NULL in the ciphersuites list.  This is a cheap and lazy way of
		// effectively removing the element.  If something *does* negotiate NULL then there are *serious*
		// problems.
		for i := 0; i < len(cipherSuites) && handshakeSuccess == true; i++ {
			if cipherSuites[i] == selectedSuite {
				cipherSuites[i] = 0xFFFF // non-existant ciphersuite
			}
		}
	}

	// Try all the TLS versions
	for tlsMin < tlsMax {
		// Let's be nice and use the preferredSuites that we already know about...
		// Deliberately use tlsMax for both values to force this version of TLS
		_, handshakeSuccess = makeTLSConnection(preferredSuites, tlsMax, tlsMax, *host)
		// Lower the max until we find all supported (and unsupported) TLS versions
		if handshakeSuccess == true {
			tlsSupport = append(tlsSupport, tlsNumtoName[tlsMax])
		}
		tlsMax--
	}

	// Make some output
	var outputStruct jsonOutput
	outputStruct.CipherSuites = preferredSuitesHuman
	outputStruct.TLSVersions = tlsSupport
	jsonOutput, _ := json.Marshal(outputStruct)
	textOutput := string(jsonOutput)
	fmt.Printf("%s", textOutput)
}
