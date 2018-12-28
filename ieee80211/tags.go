package ieee80211

// Tag is a struct for one tag
type Tag struct {
	Type   byte
	Length uint8
	Data   []byte
}

// Tags is a slice for many tags
type Tags []Tag

func decodeTags(data []byte) (tags Tags) {
	if len(data) == 0 {
		return
	}
	buf := make([]byte, len(data))
	copy(buf, data)
	for {
		if len(buf) < 2 {
			break
		}

		tag := Tag{
			Type:   buf[0],
			Length: buf[1],
			Data:   buf[2 : buf[1]+2],
		}
		tags = append(tags, tag)
		buf = buf[tag.Length+2:]
	}

	return
}

// SSID - function returning SSID from tags
func (tags Tags) SSID() string {
	for _, tag := range tags {
		if tag.Type == 0 {
			return string(tag.Data)
		}
	}
	return ""
}
