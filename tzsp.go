package tzsp

import (
	"encoding/binary"
)

// Version TZSP is always 0x01
const Version uint8 = 0x01

// Header types
const (
	HeaderTypeReceivedTagList byte = iota
	HeaderTypePacketForTransmut
	HeaderTypeReserved
	HeaderTypeConfuration
	HeaderTypeKeepalive
	HeaderTypePortOpener
)

// Encapsulated protocols
const (
	EncapsulatedProtocolEthernet    uint16 = 0x01
	EncapsulatedProtocolIEEE802_11  uint16 = 0x12
	EncapsulatedProtocolPrismHeader uint16 = 0x77
	EncapsulatedProtocolWLANAVS     uint16 = 0x7F
)

// Header is a main header struct
type Header struct {
	Version              byte
	Type                 byte
	EncapsulatedProtocol uint16
}

// Packet is a TZSP packet
type Packet struct {
	Header       Header
	TaggedFields []TaggedField
	Data         []byte
}

func decodeHeader(data []byte) (header Header, err error) {

	if header.Version = data[0]; header.Version != Version {
		err = ErrUnknownHeaderVersion
		return
	}
	header.Type = data[1]
	switch header.Type {
	case HeaderTypeReceivedTagList,
		HeaderTypePacketForTransmut,
		HeaderTypeReserved,
		HeaderTypeConfuration,
		HeaderTypeKeepalive,
		HeaderTypePortOpener:
	default:
		err = ErrUnknownHeaderType
		return
	}
	header.EncapsulatedProtocol = binary.BigEndian.Uint16(data[2:3])
	switch header.EncapsulatedProtocol {
	case EncapsulatedProtocolEthernet,
		EncapsulatedProtocolIEEE802_11,
		EncapsulatedProtocolPrismHeader,
		EncapsulatedProtocolWLANAVS:
	default:
		err = ErrUnknownEncapsulatedProtocol
		return
	}
	return
}

// DecodeBytes - function decode packet bytes to TZSP packet
func DecodeBytes(data []byte) (packet Packet, err error) {
	if data == nil || len(data) == 0 {
		err = ErrDataIsEmpty
		return
	}
	if len(data) < 4 {
		err = ErrDataIsTooShort
		return
	}
	if packet.Header, err = decodeHeader(data[:5]); err != nil {
		return
	}
	if packet.TaggedFields, packet.Data, err = decodeFields(data[5:]); err != nil {
		return
	}

	return
}
