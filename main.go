package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"github.com/spacemonkeygo/openssl"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"time"
)

var xmppClientIdent string = "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='%s' version='1.0'>\n"

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
			log.Println(string(buf))
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
	_, err := conn.Write([]byte("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>\n"))
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if !bytes.Contains(buf, []byte("<proceed")) {
		return nil, errors.New("Server did not accept starttls.")
	}
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

func StartServerTLS(conn net.Conn) error {
	return nil
}

func main() {
	bind := flag.String("bind", "127.0.0.1:5222", "local host:port to serve")
	host := flag.String("host", "", "override xmpp hostname sent in protocol")
	certPath := flag.String("cert", "", "path to SSL cert to serve to connecting clients")
	keyPath := flag.String("key", "", "path to SSL private key")
	verbose := flag.Bool("verbose", false, "verbose output")
	flag.Parse()

	if certPath != nil {

	}

	if keyPath != nil {

	}

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
			/*
				err := StartServerTLS(client)
				if err != nil {
					log.Println(err)
					return
				}
			*/
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
