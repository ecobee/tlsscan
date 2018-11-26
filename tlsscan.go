package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
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

func cipherSuiteTest(cipherSuites []uint16, tlsMin uint16, tlsMax uint16, host string) (uint16, bool) {

	// Work out how large our (almost) static packet is going to be.  Only the ciphersuites and the hostname
	// for SNI will determine the size.  58 bytes is the static portion of the packet
	var selectedCipher uint16
	hostname := strings.Split(host, ":")[0]
	packetSize := (len(cipherSuites) * 2) + len(hostname) + 59
	packet := make([]byte, packetSize)

	offset := copy(packet, []byte{0x16}) // TLS Handshake

	binary.BigEndian.PutUint16(packet[offset:], uint16(tlsMin)) // Minimum TLS Version
	offset += 2

	binary.BigEndian.PutUint16(packet[offset:], uint16(packetSize-5)) // Length
	offset += 2

	offset += copy(packet[offset:], []byte{0x01}) // HandShake Type (client hello)
	offset += copy(packet[offset:], []byte{0x00}) // Padding masquerading as length ;)

	binary.BigEndian.PutUint16(packet[offset:], uint16(packetSize-9)) // The actual length
	offset += 2

	binary.BigEndian.PutUint16(packet[offset:], uint16(tlsMax)) // Max TLS Version
	offset += 2

	rand.Read(packet[offset:32]) // 32 bytes of random
	offset += 32

	offset += copy(packet[offset:], []byte{0x00}) // Session ID length

	binary.BigEndian.PutUint16(packet[offset:], uint16(len(cipherSuites)*2)) // Length of ciphersuites field
	offset += 2

	for _, suite := range cipherSuites {
		binary.BigEndian.PutUint16(packet[offset:], suite) // Supported ciphersuites list
		offset += 2
	}

	offset += copy(packet[offset:], []byte{0x01}) // Compression Methods Length
	offset += copy(packet[offset:], []byte{0x00}) // Compression method of null

	binary.BigEndian.PutUint16(packet[offset:], uint16(len(hostname)+9)) // Real Length
	offset += 2

	offset += copy(packet[offset:], []byte{0x00, 0x00}) // SNI Extension

	binary.BigEndian.PutUint16(packet[offset:], uint16(len(hostname)+5)) // Extensions Length
	offset += 2

	binary.BigEndian.PutUint16(packet[offset:], uint16(len(hostname)+3)) // Hostname Section Length
	offset += 2

	offset += copy(packet[offset:], []byte{0x00}) // SNI Type (DNS)

	binary.BigEndian.PutUint16(packet[offset:], uint16(len(hostname))) // Hostname Length
	offset += 2

	offset += copy(packet[offset:], string(hostname))

	// And make a connection.....
	conn, err := net.Dial("tcp", host)

	// Quick error check
	if err != nil {
		// Could not connect, burn it all down!!!
		if conn != nil {
			defer conn.Close()
		}
		log.Printf("Connection failed: %v", err)
		return 0x000, false
	}

	// Send a packet...
	_, err = conn.Write(packet)
	if err != nil {
		// Could not connect, burn it all down!!!
		defer conn.Close()
		log.Printf("Connection failed: %v", err)
		return 0x000, false
	}

	// ... and get a reply?
	buffer := make([]byte, 65535)
	_, err = conn.Read(buffer)

	// Super quick check that this is a good response
	// The buffer is bigger than the packet, but pre-filled with 0's.  If we go off the end, we'll
	// just end up returning 00's
	// 0 = content type (0x16 is TLS handshake)
	// 1 = First byte (of two) of the TLS version.... They all start with 0x03 :)
	// 5 = TLS Handshake type (0x02 is server hello)
	if buffer[0] == 0x16 && buffer[1] == 0x03 && buffer[5] == 0x02 {
		// buffer[43] is the location of the offset to the selected ciphersuite.
		// so we return whatever is at this offset further than it is, clear?  Great!
		selectedCipher = binary.BigEndian.Uint16(buffer[44+buffer[43]:])
		return selectedCipher, true
	}

	// Otherwise something went wrong
	return 0x0000, false

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
		selectedSuite, handshakeSuccess = cipherSuiteTest(cipherSuites, tlsMin, tlsMax, *host)
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
