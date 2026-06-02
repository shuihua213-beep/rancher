package guid_test

import (
	"testing"

	"github.com/rancher/rancher/pkg/auth/providers/activedirectory/guid"
)

var testUUID = "3d0ef6af-965b-44e3-8fea-b23a7d3aa6cb"
var testBytes = []byte("\xaf\xf6\x0e=[\x96\xe3D\x8f\xea\xb2:}:\xa6\xcb")

func BenchmarkParse(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = guid.Parse(testUUID)
	}
}

func BenchmarkUUID(b *testing.B) {
	g, _ := guid.New(testBytes)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = g.UUID()
	}
}

func BenchmarkHex(b *testing.B) {
	g, _ := guid.New(testBytes)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = g.Hex()
	}
}

func BenchmarkEscape(b *testing.B) {
	g, _ := guid.New(testBytes)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		guid.Escape(g)
	}
}
