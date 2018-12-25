package tzsp

import (
	"bytes"
)

// Field types
const (
	TaggedFieldTypePadding            byte = 0x00
	TaggedFieldTypeEnd                byte = 0x01
	TaggedFieldTypeRawRSSI            byte = 0x0a
	TaggedFieldTypeSNR                byte = 0x0b
	TaggedFieldTypeDataRate           byte = 0x0c
	TaggedFieldTypeTimestamp          byte = 0x0d
	TaggedFieldTypeContentionFree     byte = 0x0f
	TaggedFieldTypeDecrypted          byte = 0x10
	TaggedFieldTypeFCSError           byte = 0x11
	TaggedFieldTypeRxChannel          byte = 0x12
	TaggedFieldTypePacketCount        byte = 0x28
	TaggedFieldTypeRxFrameLength      byte = 0x29
	TaggedFieldTypeWLANRadioHDRSerial byte = 0x3c
)

// TaggedField - is a one tagged field for TZSP protocol body
type TaggedField struct {
	TagType   byte
	TagLength byte
	Data      []byte
}

func (field *TaggedField) read(data []byte) (pack []byte) {
	field.TagLength = data[1]
	field.Data = data[2 : field.TagLength+2]
	pack = data[field.TagLength+2:]
	return
}

func decodeFields(data []byte) (fields []TaggedField, pack []byte, err error) {
	if data == nil || len(data) == 0 {
		err = ErrDataIsTooShort
		return
	}
	buf := make([]byte, len(data))
	copy(buf, data)
	for {
		if len(buf) == 0 {
			break
		}
		tagType := buf[0]
		field := TaggedField{
			TagType: tagType,
		}
		switch tagType {
		case TaggedFieldTypePadding:
			fields = append(fields, field)
			buf = buf[1:]
		case TaggedFieldTypeEnd:
			fields = append(fields, field)
			pack = buf[1:]
			return
		case
			TaggedFieldTypeRawRSSI,
			TaggedFieldTypeSNR,
			TaggedFieldTypeDataRate,
			TaggedFieldTypeTimestamp,
			TaggedFieldTypeContentionFree,
			TaggedFieldTypeDecrypted,
			TaggedFieldTypeFCSError,
			TaggedFieldTypeRxChannel,
			TaggedFieldTypePacketCount,
			TaggedFieldTypeRxFrameLength,
			TaggedFieldTypeWLANRadioHDRSerial:
			buf = field.read(buf)
			fields = append(fields, field)
		default:
			err = ErrUnknownFieldType
			return
		}
	}
	return
}

// Encode function encode given field
func (field *TaggedField) Encode() (data []byte, err error) {
	buf := &bytes.Buffer{}

	switch field.TagType {
	case TaggedFieldTypePadding, TaggedFieldTypeEnd:
		err = buf.WriteByte(field.TagType)
	default:
		var d []byte
		d = append(d, field.TagType, field.TagLength)
		d = append(d, field.Data...)
		_, err = buf.Write(d)
	}
	if err == nil {
		data = buf.Bytes()
	}
	return
}
