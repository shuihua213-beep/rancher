package guid

import (
	"errors"
	"regexp"
	"strings"
)

var uuidRegex = regexp.MustCompile("(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

const lowerHex = "0123456789abcdef"
const upperHex = "0123456789ABCDEF"

type GUID []byte

func (g GUID) Bytes() []byte {
	return g
}

func (g GUID) String() string {
	return g.UUID()
}

func (g GUID) UUID() string {
	if len(g) != 16 {
		return ""
	}
	var buf [36]byte
	buf[0] = lowerHex[g[3]>>4]
	buf[1] = lowerHex[g[3]&0x0f]
	buf[2] = lowerHex[g[2]>>4]
	buf[3] = lowerHex[g[2]&0x0f]
	buf[4] = lowerHex[g[1]>>4]
	buf[5] = lowerHex[g[1]&0x0f]
	buf[6] = lowerHex[g[0]>>4]
	buf[7] = lowerHex[g[0]&0x0f]
	buf[8] = '-'
	buf[9] = lowerHex[g[5]>>4]
	buf[10] = lowerHex[g[5]&0x0f]
	buf[11] = lowerHex[g[4]>>4]
	buf[12] = lowerHex[g[4]&0x0f]
	buf[13] = '-'
	buf[14] = lowerHex[g[7]>>4]
	buf[15] = lowerHex[g[7]&0x0f]
	buf[16] = lowerHex[g[6]>>4]
	buf[17] = lowerHex[g[6]&0x0f]
	buf[18] = '-'
	buf[19] = lowerHex[g[8]>>4]
	buf[20] = lowerHex[g[8]&0x0f]
	buf[21] = lowerHex[g[9]>>4]
	buf[22] = lowerHex[g[9]&0x0f]
	buf[23] = '-'
	for i := 0; i < 6; i++ {
		buf[24+i*2] = lowerHex[g[10+i]>>4]
		buf[25+i*2] = lowerHex[g[10+i]&0x0f]
	}
	return string(buf[:])
}

func (g GUID) Hex() string {
	if len(g) == 0 {
		return ""
	}
	buf := make([]byte, 0, len(g)*3-1)
	for i, b := range g {
		if i > 0 {
			buf = append(buf, ' ')
		}
		buf = append(buf, upperHex[b>>4], upperHex[b&0x0f])
	}
	return string(buf)
}

func New(encoded []byte) (GUID, error) {
	if len(encoded) != 16 {
		return nil, errors.New("cannot create GUID from encoded bytes: invalid length")
	}
	return GUID(encoded), nil
}

func Parse(uuid string) (GUID, error) {
	if !uuidRegex.MatchString(uuid) {
		return nil, errors.New("cannot parse UUID to objectGUID: invalid format")
	}
	var buf [16]byte
	decodeHex(buf[0:4], uuid[0:8])
	decodeHex(buf[4:6], uuid[9:13])
	decodeHex(buf[6:8], uuid[14:18])
	decodeHex(buf[8:10], uuid[19:23])
	decodeHex(buf[10:16], uuid[24:36])
	buf[0], buf[3] = buf[3], buf[0]
	buf[1], buf[2] = buf[2], buf[1]
	buf[4], buf[5] = buf[5], buf[4]
	buf[6], buf[7] = buf[7], buf[6]
	result := make([]byte, 16)
	copy(result, buf[:])
	return GUID(result), nil
}

func Escape(guid GUID) string {
	if len(guid) == 0 {
		return ""
	}
	var buf strings.Builder
	buf.Grow(len(guid) * 3)
	for _, b := range guid {
		buf.WriteByte('\\')
		buf.WriteByte(lowerHex[b>>4])
		buf.WriteByte(lowerHex[b&0x0f])
	}
	return buf.String()
}

func decodeHex(dst []byte, src string) {
	for i := 0; i < len(dst); i++ {
		dst[i] = hexVal(src[i*2])<<4 | hexVal(src[i*2+1])
	}
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 0
	}
}
