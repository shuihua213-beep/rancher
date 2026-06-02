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
	"fmt"
	"regexp"
	"strings"
)

const hexTable = "0123456789abcdef"
const hexTableUpper = "0123456789ABCDEF"

var uuidRegex = regexp.MustCompile("(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

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
	if len(g) != 16 {
		return ""
	}

	buf := make([]byte, 36)
	var idx int

	idx = appendHex(buf, idx, g[3])
	idx = appendHex(buf, idx, g[2])
	idx = appendHex(buf, idx, g[1])
	idx = appendHex(buf, idx, g[0])
	buf[idx] = '-'
	idx++

	idx = appendHex(buf, idx, g[5])
	idx = appendHex(buf, idx, g[4])
	buf[idx] = '-'
	idx++

	idx = appendHex(buf, idx, g[7])
	idx = appendHex(buf, idx, g[6])
	buf[idx] = '-'
	idx++

	idx = appendHex(buf, idx, g[8])
	idx = appendHex(buf, idx, g[9])
	buf[idx] = '-'
	idx++

	idx = appendHex(buf, idx, g[10])
	idx = appendHex(buf, idx, g[11])
	idx = appendHex(buf, idx, g[12])
	idx = appendHex(buf, idx, g[13])
	idx = appendHex(buf, idx, g[14])
	idx = appendHex(buf, idx, g[15])

	return string(buf)
}

// Hex returns the Hex string representation: "33 22 11 00 55 44 77 66 88 99 AA BB CC DD EE FF"
func (g GUID) Hex() string {
	if len(g) == 0 {
		return ""
	}

	bufLen := len(g)*3 - 1
	buf := make([]byte, bufLen)
	var idx int

	for i, b := range g {
		if i > 0 {
			buf[idx] = ' '
			idx++
		}
		buf[idx] = hexTableUpper[b>>4]
		buf[idx+1] = hexTableUpper[b&0x0f]
		idx += 2
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
	if !uuidRegex.MatchString(uuid) {
		return nil, errors.New("cannot parse UUID to objectGUID: invalid format")
	}

	compact := make([]byte, 0, 32)
	for i := 0; i < len(uuid); i++ {
		if uuid[i] != '-' {
			compact = append(compact, uuid[i])
		}
	}

	uuidBytes, err := hex.DecodeString(string(compact))
	if err != nil {
		return nil, fmt.Errorf("cannot decode uuid string '%s' to hex: %w", uuid, err)
	}

	return GUID(swap(uuidBytes)), nil
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
	var idx int

	for _, b := range guid {
		buf[idx] = '\\'
		buf[idx+1] = hexTable[b>>4]
		buf[idx+2] = hexTable[b&0x0f]
		idx += 3
	}

	return string(buf)
}

// swap will return a new array with the first three "bytes blocks" reversed
func swap(u []byte) []byte {
	if len(u) != 16 {
		return u
	}

	return []byte{
		u[3], u[2], u[1], u[0], // reverse 0-4
		u[5], u[4], // reverse 4-5
		u[7], u[6], // reverse 6-7
		u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15], // keep 8-15
	}
}

func appendHex(buf []byte, idx int, b byte) int {
	buf[idx] = hexTable[b>>4]
	buf[idx+1] = hexTable[b&0x0f]
	return idx + 2
}
