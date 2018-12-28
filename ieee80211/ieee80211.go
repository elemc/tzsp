package ieee80211

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Frame types
const (
	FrameTypeManagement = "management"
	FrameTypeControl    = "control"
	FrameTypeData       = "data"
	FrameTypeReserved   = "reserved"
)

// Frame subtypes
const (
	// Management
	FrameSubTypeAssociationRequest    = "association request"
	FrameSubTypeAssociationResponse   = "association response"
	FrameSubTypeReassociationRequest  = "reassociation request"
	FrameSubTypeReassociationResponse = "reassociation response"
	FrameSubTypeProbeRequest          = "probe request"
	FrameSubTypeProbeResponse         = "probe response"
	FrameSubTypeReserved              = "reserved"
	FrameSubTypeBeacon                = "beacon"
	FrameSubTypeATIM                  = "announcement traffic indication message"
	FrameSubTypeDiassociation         = "diassociation"
	FrameSubTypeAuthentication        = "authentication"
	FrameSubTypeDeauthentication      = "deauthentication"

	// Control
	FrameSubTypePS       = "power save"
	FrameSubTypeRTS      = "request to send"
	FrameSubTypeCTS      = "clear to send"
	FrameSubTypeACK      = "acknowledgment"
	FrameSubTypeCFEnd    = "contention free end"
	FrameSubTypeCFEndAck = "contention free end + ack"

	// Data
	FrameSubTypeData            = "data"
	FrameSubTypeDataCFAck       = "data + CF-Ack"
	FrameSubTypeDataCFPoll      = "data + CF-Poll"
	FrameSubTypeDataCFAckPoll   = "data + CF-Ack + CF-Poll"
	FrameSubTypeNoData          = "no data (null function)"
	FrameSubTypeNoDataCFAck     = "no data + CF-Ack"
	FrameSubTypeNoDataCFPoll    = "no data + CF-Poll"
	FrameSubTypeNoDataCFAckPoll = "no data + CF-Ack + CF-Poll"
)

var (
	typeMap = map[uint8]string{
		0: FrameTypeManagement,
		1: FrameTypeControl,
		2: FrameTypeData,
		4: FrameTypeReserved,
	}
	subtypeMap = map[uint8]map[uint8]string{
		0: map[uint8]string{
			0:  FrameSubTypeAssociationRequest,
			1:  FrameSubTypeAssociationResponse,
			2:  FrameSubTypeReassociationRequest,
			3:  FrameSubTypeReassociationResponse,
			4:  FrameSubTypeProbeRequest,
			5:  FrameSubTypeProbeResponse,
			8:  FrameSubTypeBeacon,
			9:  FrameSubTypeATIM,
			10: FrameSubTypeDiassociation,
			11: FrameSubTypeAuthentication,
			12: FrameSubTypeDeauthentication,
		},
		1: map[uint8]string{
			10: FrameSubTypePS,
			11: FrameSubTypeRTS,
			12: FrameSubTypeCTS,
			13: FrameSubTypeACK,
			14: FrameSubTypeCFEnd,
			15: FrameSubTypeCFEndAck,
		},
		2: map[uint8]string{
			0: FrameSubTypeData,
			1: FrameSubTypeDataCFAck,
			2: FrameSubTypeDataCFPoll,
			3: FrameSubTypeDataCFAckPoll,
			4: FrameSubTypeNoData,
			5: FrameSubTypeNoDataCFAck,
			6: FrameSubTypeNoDataCFPoll,
			7: FrameSubTypeNoDataCFAckPoll,
		},
	}
)

// FrameControl is a struct of 802.11 frame control (2 bytes)
type FrameControl struct {
	ProtocolVersion uint8
	Type            string
	TypeInt         uint8
	Subtype         string
	SubtypeInt      uint8
	ToDS            bool
	FromDS          bool
	MoreFlag        bool
	Retry           bool
	PowerManagement bool
	MoreData        bool
	WEP             bool
	Reserved        bool
}

// FrameBody is a struct for frame body parameters
type FrameBody struct {
	RawBytes                []byte
	Timestamp               uint64
	BeaconInterval          uint16
	CapabilitiesInformation uint16
	Tags                    Tags
}

// Frame is a struct of 802.11 frame
type Frame struct {
	rawFrameControl uint16
	DCID            uint16
	Addr1           net.HardwareAddr
	Addr2           net.HardwareAddr
	Addr3           net.HardwareAddr
	SequenceControl uint16
	Addr4           net.HardwareAddr
	FrameBody       FrameBody
	FCS             uint32
	FrameControl    FrameControl
}

// Decode - function decode bytes as frame struct
func Decode(data []byte) (frame Frame, err error) {
	if len(data) < 10 {
		err = fmt.Errorf("data is too short (%d), expected 24", len(data))
		return
	}

	//method := binary.LittleEndian
	method := binary.LittleEndian

	frame.rawFrameControl = method.Uint16(data[0:2])
	frame.decodeFrameControl()

	frame.DCID = method.Uint16(data[2:4])
	frame.Addr1 = net.HardwareAddr(data[4:10])

	if len(data) >= 16 {
		frame.Addr2 = net.HardwareAddr(data[10:16])
	}
	if len(data) >= 24 {
		frame.Addr3 = net.HardwareAddr(data[16:22])
		frame.SequenceControl = method.Uint16(data[22:24]) >> 4
	}

	if len(data) >= 30 && frame.FrameControl.Type == FrameTypeData {
		frame.Addr4 = net.HardwareAddr(data[24:30])
		frame.FrameBody.RawBytes = data[30:]
		//frame.FCS = method.Uint32(data[len(data)-4:])
	} else if len(data) >= 28 {
		frame.FrameBody.RawBytes = data[24:]
		//frame.FCS = method.Uint32(data[len(data)-4:])
	}
	frame.decodeFrameBody()

	return
}

func (frame *Frame) decodeFrameControl() {
	frame.FrameControl.ProtocolVersion = frame.FrameControl.ProtocolVersion | uint8(((frame.rawFrameControl>>1)&0x01)<<1)
	frame.FrameControl.ProtocolVersion = frame.FrameControl.ProtocolVersion | uint8(((frame.rawFrameControl>>2)&0x01)<<2)

	var ftype uint8
	ftype = ftype | uint8(((frame.rawFrameControl>>3)&0x01)<<1)
	ftype = ftype | uint8(((frame.rawFrameControl>>4)&0x01)<<2)
	frame.FrameControl.Type = typeMap[ftype]
	frame.FrameControl.TypeInt = ftype

	var subtype uint8
	subtype = subtype | uint8(((frame.rawFrameControl>>5)&0x01)<<1)
	subtype = subtype | uint8(((frame.rawFrameControl>>6)&0x01)<<2)
	subtype = subtype | uint8(((frame.rawFrameControl>>7)&0x01)<<3)
	subtype = subtype | uint8(((frame.rawFrameControl>>8)&0x01)<<4)

	if value, ok := subtypeMap[ftype][subtype]; !ok {
		frame.FrameControl.Subtype = fmt.Sprintf("%s (%d:%d)", FrameSubTypeReserved, ftype, subtype)
	} else {
		frame.FrameControl.Subtype = value
	}
	frame.FrameControl.SubtypeInt = subtype

	frame.FrameControl.ToDS = (frame.rawFrameControl>>9)&0x01 == 1
	frame.FrameControl.FromDS = (frame.rawFrameControl>>10)&0x01 == 1
	frame.FrameControl.MoreFlag = (frame.rawFrameControl>>11)&0x01 == 1
	frame.FrameControl.Retry = (frame.rawFrameControl>>12)&0x01 == 1
	frame.FrameControl.PowerManagement = (frame.rawFrameControl>>13)&0x01 == 1
	frame.FrameControl.MoreData = (frame.rawFrameControl>>14)&0x01 == 1
	frame.FrameControl.WEP = (frame.rawFrameControl>>15)&0x01 == 1
}

func (frame *Frame) decodeFrameBody() {
	if len(frame.FrameBody.RawBytes) == 0 {
		return // nothing to do
	}

	switch frame.FrameControl.Subtype {
	case FrameSubTypeBeacon, FrameSubTypeProbeResponse:
		if len(frame.FrameBody.RawBytes) >= 12 {
			frame.FrameBody.Timestamp = binary.LittleEndian.Uint64(frame.FrameBody.RawBytes[:8])
			frame.FrameBody.BeaconInterval = binary.LittleEndian.Uint16(frame.FrameBody.RawBytes[8:10])
			frame.FrameBody.CapabilitiesInformation = binary.LittleEndian.Uint16(frame.FrameBody.RawBytes[10:12])
			if len(frame.FrameBody.RawBytes) > 12 {
				frame.FrameBody.Tags = decodeTags(frame.FrameBody.RawBytes[12:])
			}
		}
	case FrameSubTypeProbeRequest:
		frame.FrameBody.Tags = decodeTags(frame.FrameBody.RawBytes)
	}

}
