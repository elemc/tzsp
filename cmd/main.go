package main

import (
	"flag"
	"fmt"
	"net"
	"strings"

	"github.com/elemc/tzsp"
	"github.com/sirupsen/logrus"
)

var (
	addr    string
	network string
)

func init() {
	flag.StringVar(&addr, "addr", ":54321", "set UDP server address")
	flag.StringVar(&network, "network", "udp", "set network type (udp, tcp)")
}

func main() {
	flag.Parse()

	conn, err := net.ListenPacket(network, addr)
	if err != nil {
		logrus.Fatal(err)
	}
	defer conn.Close()

	for {
		buf := make([]byte, 1024)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			logrus.Error(err)
			continue
		}
		buf = buf[:n]
		logrus.Debugf("Got packet: %s", string(buf))
		go decode(addr, buf)
	}
}

func decode(addr net.Addr, data []byte) {
	packet, err := tzsp.DecodeBytes(data)
	if err != nil {
		logrus.Errorf("Unable to decode TZSP packet: %s", err)
		return
	}

	ll := logrus.WithField("addr", addr.String()).
		WithField("type", packet.Header.Type).
		WithField("protocol", packet.Header.EncapsulatedProtocol)
	var msgs []string
	for _, field := range packet.TaggedFields {
		msgs = append(msgs, fmt.Sprintf("%d - %d: [%s]", field.TagType, field.TagLength, string(field.Data)))
	}
	msgs = append(msgs, "Data: %s", string(packet.Data))
	ll.Info(strings.Join(msgs, "\n"))
}
