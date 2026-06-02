// Package guid is used to handle the non-standard UUID from the Microsoft Active Directory.
// The objectGUID is following the DSP0134 specification, described in the
// DMTF System Management BIOS (SMBIOS) Reference Specification document:
//
//   - https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.4.0.pdf
//
// According to this spec the bytes for the time_low, time_mid and time_hi_and_version
// values follow the little endian format.
//
// The standard RFC4122 encoding for the UUID "00112233-4455-6677-8899-AABBCCDDEEFF" is:
//
//	00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF
//
// The encoding specified in DSP0134 is:
//
//	33 22 11 00 55 44 77 66 88 99 AA BB CC DD EE FF
package guid

import (
	"errors"
)

// GUID represent the UUID in the DSP0134 spec
type GUID []byte

const hexTable = "0123456789abcdef"
const hexTableUpper = "0123456789ABCDEF"

func encodeHexByte(dst []byte, b byte, table string) {
	dst[0] = table[b>>4]
	dst[1] = table[b&0x0f]
}

func decodeHexChar(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func decodeHexByte(s string, i int) (byte, bool) {
	if i+1 >= len(s) {
		return 0, false
	}
	a, ok1 := decodeHexChar(s[i])
	b, ok2 := decodeHexChar(s[i+1])
	if !ok1 || !ok2 {
		return 0, false
	}
	return (a << 4) | b, true
}

// Bytes returns the underlying bytes value
func (g GUID) Bytes() []byte {
	return g
}

// String returns UUID string representation
func (g GUID) String() string {
	return g.UUID()
}

// UUID returns the UUID string representation: "00112233-4455-6677-8899-AABBCCDDEEFF"
func (g GUID) UUID() string {
	if len(g) != 16 {
		return ""
	}

	var buf [36]byte
	encodeHexByte(buf[0:2], g[3], hexTable)
	encodeHexByte(buf[2:4], g[2], hexTable)
	encodeHexByte(buf[4:6], g[1], hexTable)
	encodeHexByte(buf[6:8], g[0], hexTable)
	buf[8] = '-'
	encodeHexByte(buf[9:11], g[5], hexTable)
	encodeHexByte(buf[11:13], g[4], hexTable)
	buf[13] = '-'
	encodeHexByte(buf[14:16], g[7], hexTable)
	encodeHexByte(buf[16:18], g[6], hexTable)
	buf[18] = '-'
	encodeHexByte(buf[19:21], g[8], hexTable)
	encodeHexByte(buf[21:23], g[9], hexTable)
	buf[23] = '-'
	encodeHexByte(buf[24:26], g[10], hexTable)
	encodeHexByte(buf[26:28], g[11], hexTable)
	encodeHexByte(buf[28:30], g[12], hexTable)
	encodeHexByte(buf[30:32], g[13], hexTable)
	encodeHexByte(buf[32:34], g[14], hexTable)
	encodeHexByte(buf[34:36], g[15], hexTable)

	return string(buf[:])
}

// Hex returns the Hex string representation: "33 22 11 00 55 44 77 66 88 99 AA BB CC DD EE FF"
func (g GUID) Hex() string {
	if len(g) == 0 {
		return ""
	}

	buf := make([]byte, len(g)*3-1)
	for i, b := range g {
		if i > 0 {
			buf[i*3-1] = ' '
		}
		encodeHexByte(buf[i*3:i*3+2], b, hexTableUpper)
	}

	return string(buf)
}

// New returns a GUID object
func New(encoded []byte) (GUID, error) {
	if len(encoded) != 16 {
		return nil, errors.New("cannot create GUID from encoded bytes: invalid length")
	}

	return GUID(encoded), nil
}

// Parse returns a GUID object from a RFC4122 UUID string
func Parse(uuid string) (GUID, error) {
	if len(uuid) != 36 || uuid[8] != '-' || uuid[13] != '-' || uuid[18] != '-' || uuid[23] != '-' {
		return nil, errors.New("cannot parse UUID to objectGUID: invalid format")
	}

	g := make(GUID, 16)
	var ok bool

	if g[3], ok = decodeHexByte(uuid, 0); !ok {
		return nil, errors.New("cannot parse UUID to objectGUID: invalid format")
	}
	if g[2], ok = decodeHexByte(uuid, 2); !ok {
		return nil, errors.New("cannot parse UUID to objectGUID: invalid format")
	}
	if g[1], ok = decodeHexByte(uuid, 4); !ok {
		return nil, errors.New("cannot parse UUID to objectGUID: invalid format")
	}
	if g[0], ok = decodeHexByte(uuid, 6); !ok {
		return nil, errors.New("cannot parse UUID to objectGUID: invalid format")
	}

	if g[5], ok = decodeHexByte(uuid, 9); !ok {
		return nil, errors.New("cannot parse UUID to objectGUID: invalid format")
	}
	if g[4], ok = decodeHexByte(uuid, 11); !ok {
		return nil, errors.New("cannot parse UUID to objectGUID: invalid format")
	}

	if g[7], ok = decodeHexByte(uuid, 14); !ok {
		return nil, errors.New("cannot parse UUID to objectGUID: invalid format")
	}
	if g[6], ok = decodeHexByte(uuid, 16); !ok {
		return nil, errors.New("cannot parse UUID to objectGUID: invalid format")
	}

	if g[8], ok = decodeHexByte(uuid, 19); !ok {
		return nil, errors.New("cannot parse UUID to objectGUID: invalid format")
	}
	if g[9], ok = decodeHexByte(uuid, 21); !ok {
		return nil, errors.New("cannot parse UUID to objectGUID: invalid format")
	}

	if g[10], ok = decodeHexByte(uuid, 24); !ok {
		return nil, errors.New("cannot parse UUID to objectGUID: invalid format")
	}
	if g[11], ok = decodeHexByte(uuid, 26); !ok {
		return nil, errors.New("cannot parse UUID to objectGUID: invalid format")
	}
	if g[12], ok = decodeHexByte(uuid, 28); !ok {
		return nil, errors.New("cannot parse UUID to objectGUID: invalid format")
	}
	if g[13], ok = decodeHexByte(uuid, 30); !ok {
		return nil, errors.New("cannot parse UUID to objectGUID: invalid format")
	}
	if g[14], ok = decodeHexByte(uuid, 32); !ok {
		return nil, errors.New("cannot parse UUID to objectGUID: invalid format")
	}
	if g[15], ok = decodeHexByte(uuid, 34); !ok {
		return nil, errors.New("cannot parse UUID to objectGUID: invalid format")
	}

	return g, nil
}

// Escape returns an escaped string format of the objectGUID that can be safely used
// through the LDAP search. Every byte has to be encoded in an hex string,
// and prefixed with the '\' character. If a byte has a hex encoded string of
// length 1 then it will be prefixed with a '0'.
func Escape(guid GUID) string {
	if len(guid) == 0 {
		return ""
	}

	buf := make([]byte, len(guid)*3)
	for i, b := range guid {
		buf[i*3] = '\\'
		encodeHexByte(buf[i*3+1:i*3+3], b, hexTable)
	}

	return string(buf)
}
