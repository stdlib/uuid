package uuid

import (
	"testing"

	gofrs "github.com/gofrs/uuid"
	guuid "github.com/google/uuid"
)

// our v1
func BenchmarkUUIDv1_Ours(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewV1()
	}
}

// google v1
func BenchmarkUUIDv1_Google(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = guuid.NewUUID()
	}
}

// gofrs v1
func BenchmarkUUIDv1_Gofrs(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = gofrs.NewV1()
	}
}

// our v2
func BenchmarkUUIDv2_Ours(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewV2(0x00)
	}
}

// google v2
func BenchmarkUUIDv2_Google(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = guuid.NewDCEPerson()
	}
}

// our v3
func BenchmarkUUIDv3_Ours(b *testing.B) {
	ns := NewV4()
	name := "benchmark-test"
	for i := 0; i < b.N; i++ {
		_ = NewV3(ns, name)
	}
}

// google v3
func BenchmarkUUIDv3_Google(b *testing.B) {
	ns, _ := guuid.NewRandom()
	name := "benchmark-test"
	for i := 0; i < b.N; i++ {
		_ = guuid.NewMD5(ns, []byte(name))
	}
}

// gofrs v3
func BenchmarkUUIDv3_Gofrs(b *testing.B) {
	ns, _ := gofrs.NewV4()
	name := "benchmark-test"
	for i := 0; i < b.N; i++ {
		_ = gofrs.NewV3(ns, name)
	}
}

// our v4
func BenchmarkUUIDv4_Our(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewV4()
	}
}

func BenchmarkUUIDv4_OurPool(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewV4Pool()
	}
}

func BenchmarkUUIDv4_OurFastMathV2(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewV4Fast()
	}
}

// google v4
func BenchmarkUUIDv4_Google(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = guuid.NewRandom()
	}
}

// gofrs v4
func BenchmarkUUIDv4_Gofrs(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = gofrs.NewV4()
	}
}

// our v5
func BenchmarkUUIDv5_Our(b *testing.B) {
	ns := NewV4()
	name := "benchmark-test"
	for i := 0; i < b.N; i++ {
		_ = NewV5(ns, name)
	}
}

// google v5
func BenchmarkUUIDv5_Google(b *testing.B) {
	ns, _ := guuid.NewRandom()
	name := "benchmark-test"
	for i := 0; i < b.N; i++ {
		_ = guuid.NewSHA1(ns, []byte(name))
	}
}

// gofrs v5
func BenchmarkUUIDv5_Gofrs(b *testing.B) {
	ns, _ := gofrs.NewV4()
	name := "benchmark-test"
	for i := 0; i < b.N; i++ {
		_ = gofrs.NewV5(ns, name)
	}
}

// our v6
func BenchmarkUUIDv6_Our(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewV6()
	}
}

// google v6
func BenchmarkUUIDv6_Google(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = guuid.NewV6()
	}
}

// gofrs v6
func BenchmarkUUIDv6_Gofrs(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = gofrs.NewV6()
	}
}

// our v7
func BenchmarkUUIDv7_Our(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewV7()
	}
}

// google v7
func BenchmarkUUIDv7_Google(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = guuid.NewV7()
	}
}

// gofrs v7
func BenchmarkUUIDv7_Gofrs(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = gofrs.NewV7()
	}
}
