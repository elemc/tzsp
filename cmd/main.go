package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"

	"github.com/elemc/tzsp"
	"github.com/elemc/tzsp/ieee80211"
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
	logrus.SetLevel(logrus.DebugLevel)

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
		} else if n == 0 {
			break
		}
		buf = buf[:n]
		go decode(addr, buf)
		//break
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
	for _, field := range packet.TaggedFields {
		switch field.TagType {
		case tzsp.TaggedFieldTypeRawRSSI:
			ll = ll.WithField("signal", int(field.Data[0])-256)
		case tzsp.TaggedFieldTypeDataRate:
			ll = ll.WithField("rate", tzsp.DataRate(field.Data[0]).String())
		case tzsp.TaggedFieldTypeFCSError:
			ll = ll.WithField("FCS", field.Data[0] == 0)
		case tzsp.TaggedFieldTypeRxChannel:
			ll = ll.WithField("channel", field.Data[0])
		case tzsp.TaggedFieldTypeRxFrameLength:
			ll = ll.WithField("length", binary.BigEndian.Uint16(field.Data))
		case tzsp.TaggedFieldTypeEnd:
			continue
		default:
			ll = ll.WithField(fmt.Sprintf("%02x", field.TagType), field.Data)
		}
	}
	if packet.Data != nil && len(packet.Data) > 0 {
		frame, err := ieee80211.Decode(packet.Data)
		if err != nil {
			ll.Errorf("Unable to decode IEEE 802.11 frame: %s", err)
			return
		}
		ll =
			ll.WithField("destination", frame.Addr1.String()).
				WithField("source", frame.Addr2.String()).
				WithField("bss_id", frame.Addr3.String()).
				WithField("seq", frame.SequenceControl).
				WithField("fcp-type", frame.FrameControl.Type+" "+frame.FrameControl.Subtype).
				WithField("d/c-id", frame.DCID).
				WithField("to_ds", frame.FrameControl.ToDS).
				WithField("from_ds", frame.FrameControl.FromDS)
		if len(frame.Addr4) > 0 {
			ll = ll.WithField("addr4", frame.Addr4.String())
		}
	}
	ll.Info("data")
}
