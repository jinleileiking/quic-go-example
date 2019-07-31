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
	mrand "math/rand"
	"os"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/op/go-logging"
	"github.com/pkg/errors"
)

var log = logging.MustGetLogger("example")

var format = logging.MustStringFormatter(
	`%{color}%{time:15:04:05.000} %{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}`,
)

var serverInfo = flag.String("s", "localhost:6666", "quic server host and port")
var typ = flag.String("t", "server", "quic server or client. Client will send a message and waiting for receiving a message. Server will receive a message and echo back")
var intval = flag.Int("intval", 1000, "[client] send intval ms")
var cnt = flag.Int("c", 1, "[client] send count")
var message = flag.String("m", "hello gquic from client", "[client] send content")
var isRandom = flag.Bool("r", false, "[client] use random string, works with rlen")
var rlen = flag.Int("rlen", 10, "[client] random string len, works with r")
var dump = flag.Bool("d", false, "dump content?")
var echo = flag.Bool("e", true, "echo / check  echo the data?")

func initLog() {

	backend1 := logging.NewLogBackend(os.Stderr, "", 0)
	backend2 := logging.NewLogBackend(os.Stderr, "", 0)

	backend2Formatter := logging.NewBackendFormatter(backend2, format)

	backend1Leveled := logging.AddModuleLevel(backend1)
	backend1Leveled.SetLevel(logging.ERROR, "")

	logging.SetBackend(backend1Leveled, backend2Formatter)
}

func main() {
	initLog()
	flag.Parse()

	if *typ == "client" {
		err := client(*serverInfo)
		if err != nil {
			panic(err)
		}
		log.Info("Done")
		return
	}

	if *typ == "server" {
		err := server(*serverInfo)
		if err != nil {
			panic(err)
		}
		log.Info("Done")
		return
	}

	log.Error("type must be server or client")
}

type loggingWriter struct{ io.Writer }

func (w loggingWriter) Write(b []byte) (int, error) {
	if *dump {
		log.Infof("Got and send '%s'\n", string(b))
	}
	return w.Writer.Write(b)
}

type loggingReader struct{ io.Reader }

func (w loggingReader) Read(b []byte) (int, error) {
	if *dump {
		log.Infof("Got '%s'\n", string(b))
	}
	return w.Reader.Read(b)
}

func server(serverInfo string) error {
	listener, err := quic.ListenAddr(serverInfo, generateTLSConfig(), &quic.Config{IdleTimeout: 50 * time.Minute})
	log.Info("Listen done")
	if err != nil {
		return err
	}

	for {
		log.Info("Accept started")
		sess, err := listener.Accept()
		if err != nil {
			return err
		}
		log.Info("Accept done")

		go func() {
			stream, err := sess.AcceptStream()
			if err != nil {
				log.Errorf("AcceptStream error %s\n", err.Error())
			}

			if *echo {
				// var n int64
				// log.Warning("ioCopy ..........")
				n, err = io.Copy(loggingWriter{stream}, stream)

				recvBuf := make(chan []byte, 1000)

				go func() {
					var n int
					buf := make([]byte, 10000)
					for {
						log.Error("-----------------------------Read-------------------\n")
						if n, err = io.ReadFull(stream, buf); err != nil {
							log.Errorf("io.Read error %s\n", err.Error())
							return
						}
						log.Errorf("-----------------------------Read %d bytes------done\n", n)
						recvBuf <- buf
						log.Errorf("-----------------------------Sending channel------done\n", n)
					}
				}()

				go func() {
					for {
						buf := <-recvBuf
						var writeBytes int
						log.Error("-----------------------------Write-------------------\n")
						writeBytes, err = stream.Write(buf)
						if err != nil {
							log.Error("stream.Write failed")
							return
						}
						log.Error("-------------------------write Done, bytes:", writeBytes)

					}
				}()

				// log.Warning("ioCopy done......")
			} else {
				var n int
				buf := make([]byte, 10000)
				for {
					if n, err = io.ReadFull(loggingReader{stream}, buf); err != nil {
						log.Errorf("io.Read error %s\n", err.Error())
					}
					log.Infof("Read %d bytes\n", n)
				}
			}
			return
		}()
	}

}

func client(serverInfo string) error {
	log.Info("Dialing....")
	session, err := quic.DialAddr(serverInfo, &tls.Config{InsecureSkipVerify: true}, &quic.Config{IdleTimeout: 50 * time.Minute})
	if err != nil {
		return err
	}

	log.Info("Dial Ok")

	stream, err := session.OpenStreamSync()
	if err != nil {
		return errors.Wrap(err, "OpenStreamSync failed")
	}

	log.Info("Sync Ok")

	msg := *message

	for c := 0; c < *cnt; c++ {
		if *isRandom {
			msg = RandStringRunes(*rlen)
		}

		if *dump {
			log.Infof("Client: Snd '%s', count : %d\n", msg, c)
		} else {
			log.Infof("Client: Snd count : %d\n", c)
		}
		startTime := time.Now()
		var writeBytes int
		writeBytes, err = stream.Write([]byte(msg))
		if err != nil {
			return errors.Wrap(err, "stream.Write failed")
		}
		log.Info("Done, bytes:", writeBytes)

		if *echo {
			log.Info("waiting for receive.............")
			var n int

			buf := make([]byte, len(msg))
			var rcvTotalLen int

			for rcvTotalLen < len(msg) {
				log.Warning("Reading......")
				n, err = stream.Read(buf[rcvTotalLen:])
				log.Warning("Reading......done")
				// n, err = stream.Read(buf)

				rcvTotalLen += n
				if err != nil {
					return errors.Wrap(err, "io.Read error")
				}

				if *dump {
					log.Infof("Client: Got %d bytes: '%s'\n", n, buf)
				} else {
					log.Infof("Client: Got %d bytes\n", n)
				}

			}

			if string(buf) != msg {
				log.Errorf("send and receive is not same\n send:%s\n recv:%s\n", msg, buf)
			}

		}

		elapsed := time.Since(startTime)
		log.Infof("Cost: %s\n", elapsed)

		if *cnt != 1 {
			time.Sleep(time.Duration(*intval) * time.Millisecond)
		}
	}

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

func init() {
	mrand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[mrand.Intn(len(letterRunes))]
	}
	return string(b)
}
