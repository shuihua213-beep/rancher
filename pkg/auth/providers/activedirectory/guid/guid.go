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
	"encoding/hex"
	"errors"
)

const (
	encodedLen    = 16
	uuidStringLen = 36
	lowerHexTable = "0123456789abcdef"
	upperHexTable = "0123456789ABCDEF"
)

var (
	errInvalidLength = errors.New("cannot create GUID from encoded bytes: invalid length")
	errInvalidFormat = errors.New("cannot parse UUID to objectGUID: invalid format")
)

// GUID represent the UUID in the DSP0134 spec
type GUID []byte

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
	if len(g) != encodedLen {
		return ""
	}

	var raw [encodedLen]byte
	raw[0], raw[1], raw[2], raw[3] = g[3], g[2], g[1], g[0]
	raw[4], raw[5] = g[5], g[4]
	raw[6], raw[7] = g[7], g[6]
	copy(raw[8:], g[8:])

	var buf [uuidStringLen]byte
	hex.Encode(buf[0:8], raw[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], raw[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], raw[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], raw[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:36], raw[10:16])

	return string(buf[:])
}

// Hex returns the Hex string representation: "33 22 11 00 55 44 77 66 88 99 AA BB CC DD EE FF"
func (g GUID) Hex() string {
	if len(g) == 0 {
		return ""
	}

	buf := make([]byte, len(g)*3-1)
	pos := 0
	for i, b := range g {
		if i > 0 {
			buf[pos] = ' '
			pos++
		}
		encodeHexByte(buf[pos:pos+2], b, upperHexTable)
		pos += 2
	}

	return string(buf)
}

// New returns a GUID object
func New(encoded []byte) (GUID, error) {
	if len(encoded) != encodedLen {
		return nil, errInvalidLength
	}

	return GUID(encoded), nil
}

// Parse returns a GUID object from a RFC4122 UUID string
func Parse(uuid string) (GUID, error) {
	if len(uuid) != uuidStringLen || uuid[8] != '-' || uuid[13] != '-' || uuid[18] != '-' || uuid[23] != '-' {
		return nil, errInvalidFormat
	}

	guid := make([]byte, encodedLen)
	var ok bool

	if guid[0], ok = decodeHexByte(uuid, 6); !ok {
		return nil, errInvalidFormat
	}
	if guid[1], ok = decodeHexByte(uuid, 4); !ok {
		return nil, errInvalidFormat
	}
	if guid[2], ok = decodeHexByte(uuid, 2); !ok {
		return nil, errInvalidFormat
	}
	if guid[3], ok = decodeHexByte(uuid, 0); !ok {
		return nil, errInvalidFormat
	}
	if guid[4], ok = decodeHexByte(uuid, 11); !ok {
		return nil, errInvalidFormat
	}
	if guid[5], ok = decodeHexByte(uuid, 9); !ok {
		return nil, errInvalidFormat
	}
	if guid[6], ok = decodeHexByte(uuid, 16); !ok {
		return nil, errInvalidFormat
	}
	if guid[7], ok = decodeHexByte(uuid, 14); !ok {
		return nil, errInvalidFormat
	}
	if guid[8], ok = decodeHexByte(uuid, 19); !ok {
		return nil, errInvalidFormat
	}
	if guid[9], ok = decodeHexByte(uuid, 21); !ok {
		return nil, errInvalidFormat
	}
	if guid[10], ok = decodeHexByte(uuid, 24); !ok {
		return nil, errInvalidFormat
	}
	if guid[11], ok = decodeHexByte(uuid, 26); !ok {
		return nil, errInvalidFormat
	}
	if guid[12], ok = decodeHexByte(uuid, 28); !ok {
		return nil, errInvalidFormat
	}
	if guid[13], ok = decodeHexByte(uuid, 30); !ok {
		return nil, errInvalidFormat
	}
	if guid[14], ok = decodeHexByte(uuid, 32); !ok {
		return nil, errInvalidFormat
	}
	if guid[15], ok = decodeHexByte(uuid, 34); !ok {
		return nil, errInvalidFormat
	}

	return GUID(guid), nil
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
		pos := i * 3
		buf[pos] = '\\'
		encodeHexByte(buf[pos+1:pos+3], b, lowerHexTable)
	}

	return string(buf)
}

func encodeHexByte(dst []byte, b byte, table string) {
	dst[0] = table[b>>4]
	dst[1] = table[b&0x0f]
}

func decodeHexByte(value string, offset int) (byte, bool) {
	hi := decodeHexNibble(value[offset])
	lo := decodeHexNibble(value[offset+1])
	if hi == 0xFF || lo == 0xFF {
		return 0, false
	}

	return hi<<4 | lo, true
}

func decodeHexNibble(b byte) byte {
	switch {
	case b >= '0' && b <= '9':
		return b - '0'
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10
	default:
		return 0xFF
	}
}
