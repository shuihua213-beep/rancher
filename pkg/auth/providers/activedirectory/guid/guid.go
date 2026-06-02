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

const hextable = "0123456789abcdef"

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

	var buf [36]byte
	buf[0] = hextable[g[3]>>4]
	buf[1] = hextable[g[3]&0x0f]
	buf[2] = hextable[g[2]>>4]
	buf[3] = hextable[g[2]&0x0f]
	buf[4] = hextable[g[1]>>4]
	buf[5] = hextable[g[1]&0x0f]
	buf[6] = hextable[g[0]>>4]
	buf[7] = hextable[g[0]&0x0f]
	buf[8] = '-'
	buf[9] = hextable[g[5]>>4]
	buf[10] = hextable[g[5]&0x0f]
	buf[11] = hextable[g[4]>>4]
	buf[12] = hextable[g[4]&0x0f]
	buf[13] = '-'
	buf[14] = hextable[g[7]>>4]
	buf[15] = hextable[g[7]&0x0f]
	buf[16] = hextable[g[6]>>4]
	buf[17] = hextable[g[6]&0x0f]
	buf[18] = '-'
	buf[19] = hextable[g[8]>>4]
	buf[20] = hextable[g[8]&0x0f]
	buf[21] = hextable[g[9]>>4]
	buf[22] = hextable[g[9]&0x0f]
	buf[23] = '-'
	buf[24] = hextable[g[10]>>4]
	buf[25] = hextable[g[10]&0x0f]
	buf[26] = hextable[g[11]>>4]
	buf[27] = hextable[g[11]&0x0f]
	buf[28] = hextable[g[12]>>4]
	buf[29] = hextable[g[12]&0x0f]
	buf[30] = hextable[g[13]>>4]
	buf[31] = hextable[g[13]&0x0f]
	buf[32] = hextable[g[14]>>4]
	buf[33] = hextable[g[14]&0x0f]
	buf[34] = hextable[g[15]>>4]
	buf[35] = hextable[g[15]&0x0f]

	return string(buf[:])
}

// Hex returns the Hex string representation: "33 22 11 00 55 44 77 66 88 99 AA BB CC DD EE FF"
func (g GUID) Hex() string {
	b := g.Bytes()
	n := len(b)
	if n == 0 {
		return ""
	}

	if n == 16 {
		var buf [47]byte
		for i := 0; i < 16; i++ {
			v := b[i]
			if i > 0 {
				buf[i*3-1] = ' '
			}
			buf[i*3] = hexToUpper(v >> 4)
			buf[i*3+1] = hexToUpper(v & 0x0f)
		}
		return string(buf[:])
	}

	dst := make([]byte, n*3-1)
	for i, v := range b {
		if i > 0 {
			dst[i*3-1] = ' '
		}
		dst[i*3] = hexToUpper(v >> 4)
		dst[i*3+1] = hexToUpper(v & 0x0f)
	}
	return string(dst)
}

func hexToUpper(b byte) byte {
	if b < 10 {
		return '0' + b
	}
	return 'A' + b - 10
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

	uuid = strings.ReplaceAll(uuid, "-", "")
	uuidBytes, err := hex.DecodeString(uuid)
	if err != nil {
		return nil, fmt.Errorf("cannot decode uuid string '%s' to hex: %w", uuid, err)
	}

	uuidBytes[0], uuidBytes[3] = uuidBytes[3], uuidBytes[0]
	uuidBytes[1], uuidBytes[2] = uuidBytes[2], uuidBytes[1]
	uuidBytes[4], uuidBytes[5] = uuidBytes[5], uuidBytes[4]
	uuidBytes[6], uuidBytes[7] = uuidBytes[7], uuidBytes[6]

	return GUID(uuidBytes), nil
}

// Escape returns an escaped string format of the objectGUID that can be safely used
// through the LDAP search. Every byte has to be encoded in an hex string,
// and prefixed with the '\' character. If a byte has a hex encoded string of
// length 1 then it will be prefixed with a '0'.
func Escape(guid GUID) string {
	b := guid.Bytes()
	n := len(b)
	if n == 0 {
		return ""
	}

	builder := strings.Builder{}
	builder.Grow(n * 3)
	for _, v := range b {
		builder.WriteByte('\\')
		builder.WriteByte(hextable[v>>4])
		builder.WriteByte(hextable[v&0x0f])
	}

	return builder.String()
}
