package tzsp

import (
	"bytes"
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
	header.EncapsulatedProtocol = binary.BigEndian.Uint16(data[2:4])
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
	if packet.TaggedFields, packet.Data, err = decodeFields(data[4:]); err != nil {
		return
	}

	return
}

// EncodeBytes function encode packet to bytes
func (packet *Packet) EncodeBytes() (data []byte, err error) {
	buf := &bytes.Buffer{}

	// encode header
	if err = buf.WriteByte(packet.Header.Version); err != nil {
		return
	}
	if err = buf.WriteByte(packet.Header.Type); err != nil {
		return
	}

	var encProtocol []byte
	binary.BigEndian.PutUint16(encProtocol, packet.Header.EncapsulatedProtocol)
	if _, err = buf.Write(encProtocol); err != nil {
		return
	}

	// encode fields
	var lastFieldPresent bool
	for _, field := range packet.TaggedFields {
		if field.TagType == TaggedFieldTypeEnd {
			lastFieldPresent = true
		}
		d, err := field.Encode()
		if err != nil {
			return nil, err
		}
		if _, err = buf.Write(d); err != nil {
			return nil, err
		}
	}
	if !lastFieldPresent {
		if err = buf.WriteByte(TaggedFieldTypeEnd); err != nil {
			return
		}
	}
	data = buf.Bytes()
	return
}
