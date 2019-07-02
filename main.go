package main

import (
	"crypto/tls"
	"flag"
	"io"
	"os"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/op/go-logging"
)

const message = "foobar"

var log = logging.MustGetLogger("example")

var serverInfo = flag.String("s", "localhost:6666", "quic server host and port")

var format = logging.MustStringFormatter(
	`%{color}%{time:15:04:05.000} %{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}`,
)

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

	err := clientMain(*serverInfo)
	if err != nil {
		panic(err)
	}
}

func clientMain(serverInfo string) error {
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

	log.Info("Client: Sending '%s'\n", message)
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
	log.Info("Client: Got '%s'\n", buf)

	return nil
}
