package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io"
	"math/big"
	"os"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/op/go-logging"
)

const message = "foobar"

var log = logging.MustGetLogger("example")

var format = logging.MustStringFormatter(
	`%{color}%{time:15:04:05.000} %{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}`,
)

var serverInfo = flag.String("s", "localhost:6666", "quic server host and port")
var typ = flag.String("t", "server", "quic server or client. Client will send a message and waiting for receiving a message. Server will receive a message and echo back")

func initLog() {

	backend1 := logging.NewLogBackend(os.Stderr, "", 0)
	backend2 := logging.NewLogBackend(os.Stderr, "", 0)

	backend2Formatter := logging.NewBackendFormatter(backend2, format)

	backend1Leveled := logging.AddModuleLevel(backend1)
	backend1Leveled.SetLevel(logging.ERROR, "")

	logging.SetBackend(backend1Leveled, backend2Formatter)
}

func main() {
	flag.Parse()

	if *typ == "client" {
		err := client(*serverInfo)
		if err != nil {
			panic(err)
		}
		log.Error("Done")
	}

	if *typ == "server" {
		err := server(*serverInfo)
		if err != nil {
			panic(err)
		}
		log.Error("Done")
	}

	log.Error("type must be server or client")
}

type loggingWriter struct{ io.Writer }

func (w loggingWriter) Write(b []byte) (int, error) {
	log.Infof("Got '%s'\n", string(b))
	return w.Writer.Write(b)
}

func server(serverInfo string) error {
	listener, err := quic.ListenAddr(serverInfo, generateTLSConfig(), nil)
	log.Info("Listen done")
	if err != nil {
		return err
	}
	sess, err := listener.Accept()
	if err != nil {
		return err
	}
	log.Info("Accept done")
	stream, err := sess.AcceptStream()
	if err != nil {
		panic(err)
	}
	// Echo through the loggingWriter
	_, err = io.Copy(loggingWriter{stream}, stream)
	return err
}

func client(serverInfo string) error {
	log.Info("Dialing....")
	session, err := quic.DialAddr(serverInfo, &tls.Config{InsecureSkipVerify: true}, nil)
	if err != nil {
		return err
	}

	log.Info("Dial Ok")

	stream, err := session.OpenStreamSync()
	if err != nil {
		return err
	}

	log.Info("Sync Ok")

	log.Infof("Client: Sending '%s'\n", message)
	_, err = stream.Write([]byte(message))
	if err != nil {
		return err
	}
	log.Info("Done")

	log.Info("waiting for receive.............")
	buf := make([]byte, len(message))
	_, err = io.ReadFull(stream, buf)
	if err != nil {
		return err
	}
	log.Infof("Client: Got '%s'\n", buf)

	return nil
}

func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}
}
