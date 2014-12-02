package main

import (
	"bytes"
	"code.google.com/p/go-uuid/uuid"
	"errors"
	"flag"
	"fmt"
	"github.com/spacemonkeygo/openssl"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"regexp"
	"time"
)

var xmppClientIdent string = `<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='%s' version='1.0'>\n`
var xmppServerPreamble string = `<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' id='%s' from='%s' version='1.0' xml:lang='en'><stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'></starttls></stream:features>\n`
var xmppClientStarttls string = `<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>\n`
var xmppServerProceed string = `<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>\n`

type PrefixLogger struct {
	Prefix string
}

func (p *PrefixLogger) Write(data []byte) (int, error) {
	log.Println(p.Prefix, string(data))
	return len(data), nil
}

func NewPrefixLogger(prefix string) io.Writer {
	return &PrefixLogger{prefix}
}

var tlsFeatureMatch *regexp.Regexp = regexp.MustCompile(`<starttls xmlns=['"]urn:ietf:params:xml:ns:xmpp-tls`)

func CanStartClientTLS(conn net.Conn) bool {
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	buf := make([]byte, 10240)
	pos := 0
	var err error
	var n int
	for tlsFeatureMatch.Find(buf) == nil {
		if err != nil {
			log.Println(err)
			return false
		}
		if pos > len(buf)-64 {
			return false
		}
		if bytes.Contains(buf, []byte("/stream:features>")) {
			return false
		}
		n, err = conn.Read(buf[pos:])
		pos += n
	}
	conn.SetDeadline(*new(time.Time))
	return true
}

func StartClientTLS(conn net.Conn) (net.Conn, error) {
	if !CanStartClientTLS(conn) {
		return nil, errors.New("Failed to starttls.")
	}
	_, err := conn.Write([]byte(xmppClientStarttls))
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if !bytes.Contains(buf, []byte("<proceed")) {
		return nil, errors.New("Server did not accept starttls.")
	}
	log.Println(string(buf))
	ctx, err := openssl.NewCtx()
	if err != nil {
		return nil, err
	}
	conn, err = openssl.Client(conn, ctx)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func StartServerTLS(conn net.Conn, host string, key openssl.PrivateKey, cert *openssl.Certificate) (net.Conn, error) {
	var err error
	var n int
	guid := uuid.New()
	_, err = conn.Write([]byte(fmt.Sprintf(xmppServerPreamble, guid, host)))
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 1024)
	pos := 0
	for tlsFeatureMatch.Find(buf) == nil {
		if err != nil {
			log.Println(string(buf))
			return nil, err
		}
		if pos > len(buf)-64 {
			return nil, errors.New("client did not starttls")
		}
		n, err = conn.Read(buf[pos:])
		pos += n
	}
	_, err = conn.Write([]byte(xmppServerProceed))
	if err != nil {
		return nil, err
	}
	ctx, err := openssl.NewCtx()
	if err != nil {
		return nil, err
	}
	ctx.UseCertificate(cert)
	ctx.UsePrivateKey(key)
	conn, err = openssl.Server(conn, ctx)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func main() {
	bind := flag.String("bind", "127.0.0.1:5222", "local host:port to serve")
	host := flag.String("host", "", "override xmpp hostname sent in protocol")
	certPath := flag.String("cert", "", "path to SSL cert to serve to connecting clients")
	keyPath := flag.String("key", "", "path to SSL private key")
	verbose := flag.Bool("verbose", false, "verbose output")
	clientTls := flag.Bool("clientTls", false, "use TLS for client (implicit if key/cert are specified)")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		fmt.Fprintf(os.Stderr, "If no SSL certificate is provided, a self-signed one will be generated.\n")
		fmt.Fprintf(os.Stderr, "Example usage:\n  %s [options] <target server>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nError: <target server> required\n")
		os.Exit(1)
	}
	remote := args[0]
	remoteHost, _, err := net.SplitHostPort(remote)
	if *host != "" {
		remoteHost = *host
	}
	if err != nil {
		log.Fatal(err)
	}

	var cert *openssl.Certificate
	var key openssl.PrivateKey
	if *certPath != "" && *keyPath != "" {
		*clientTls = true
		log.Println("Using certificate:", *certPath)
		log.Println("Using key:        ", *keyPath)
		pem, err := ioutil.ReadFile(*certPath)
		if err != nil {
			log.Fatal(err)
		}
		cert, err = openssl.LoadCertificateFromPEM(pem)
		if err != nil {
			log.Fatal(err)
		}
		pem, err = ioutil.ReadFile(*keyPath)
		if err != nil {
			log.Fatal(err)
		}
		key, err = openssl.LoadPrivateKeyFromPEM(pem)
		if err != nil {
			log.Fatal(err)
		}
	} else if *clientTls {
		log.Println("Generating self-signed certificate...")
		key, err = openssl.GenerateRSAKey(2048)
		if err != nil {
			log.Fatal(err)
		}
		info := &openssl.CertificateInfo{
			Serial:       1,
			Issued:       0,
			Expires:      24 * time.Hour,
			Country:      "US",
			Organization: "xmppstrip",
			CommonName:   remoteHost,
		}
		cert, err = openssl.NewCertificate(info, key)
		if err != nil {
			log.Fatal(err)
		}
		err = cert.Sign(key, openssl.EVP_SHA256)
		if err != nil {
			log.Fatal(err)
		}
	}

	log.Printf("Binding %s to %s\n", remote, *bind)
	ln, err := net.Listen("tcp", *bind)
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Connection from:", conn.RemoteAddr())
		go func(client net.Conn) {
			var err error
			if *clientTls {
				client, err = StartServerTLS(client, remoteHost, key, cert)
				if err != nil {
					log.Println(err)
					return
				}
			}
			remoteConn, err := net.Dial("tcp", remote)
			if err != nil {
				log.Println(err)
				return
			}
			_, err = remoteConn.Write([]byte(fmt.Sprintf(xmppClientIdent, remoteHost)))
			if err != nil {
				log.Println(err)
				return
			}
			remoteConn, err = StartClientTLS(remoteConn)
			if err != nil {
				log.Println(err)
				return
			}
			toRemote := remoteConn.(io.Writer)
			toClient := client.(io.Writer)
			if *verbose {
				toRemote = io.MultiWriter(NewPrefixLogger("->"), remoteConn)
				toClient = io.MultiWriter(NewPrefixLogger("<-"), client)
			}
			go io.Copy(toRemote, client)
			go io.Copy(toClient, remoteConn)
		}(conn)
	}
}
