package uuid

import (
	"crypto/md5"
	cryptorand "crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"io"
	mathrand "math/rand/v2"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// UUID represents a 128-bit universally unique identifier (RFC 4122 and RFC 9562).
type UUID [16]byte

var (
	// Nil is the "nil" UUID, a special form of UUID that is specified to have all 128 bits set to 0.
	Nil UUID

	// Max is the "max" UUID, a special form of UUID that is specified to have all 128 bits set to 1 (RFC 9562).
	Max = UUID{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	}
)

// IsNil returns true if the UUID is equal to the nil UUID.
func (u UUID) IsNil() bool {
	return u == Nil
}

// String returns the canonical string representation of the UUID:
// xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.
func (u UUID) String() string {
	var buf [36]byte
	hex.Encode(buf[0:8], u[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], u[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], u[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], u[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:36], u[10:16])
	return string(buf[:])
}

var (
	lastTime     uint64
	clockSeq     uint16
	onceClockSeq sync.Once
)

func initClockSequence() {
	var b [2]byte
	_, _ = cryptorand.Read(b[:])
	clockSeq = binary.BigEndian.Uint16(b[:]) & 0x3FFF // 14 bit
}

const mask = 0x01B21DD213814000

// NewV1 generates a Version 1 UUID based on the current timestamp, clock sequence,
// and the node's MAC address (RFC 4122).
//
// Layout:
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                           time_low                            |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|           time_mid            |  ver  |       time_high       |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|var|         clock_seq         |             node              |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                              node                             |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func NewV1() UUID {
	onceClockSeq.Do(initClockSequence)

	var u UUID
	now := uint64(time.Now().UnixNano()/100) + mask

	timeMu.Lock()
	if now <= lastTime {
		clockSeq = (clockSeq + 1) & 0x3FFF // 14 bit
	}
	lastTime = now
	seq := clockSeq
	timeMu.Unlock()

	// time_low
	binary.BigEndian.PutUint32(u[0:], uint32(now&0xFFFFFFFF))
	// time_mid
	binary.BigEndian.PutUint16(u[4:], uint16((now>>32)&0xFFFF))

	// time_hi_and_version
	timeHi := uint16((now >> 48) & 0x0FFF)
	timeHi |= 1 << 12 // Version 1
	binary.BigEndian.PutUint16(u[6:], timeHi)

	u[8] = byte(seq >> 8)
	u[9] = byte(seq)
	u[8] = (u[8] &^ 0xC0) | 0x80

	node := mac()
	if hasMAC {
		copy(u[10:], node)
	} else {
		_, _ = cryptorand.Read(u[10:])
		u[10] |= 0x01 // multicast bit for random node
	}

	return u
}

var (
	// cache mac for use only once
	cachedMAC [6]byte
	// flag
	hasMAC bool
	// use mac() func once
	macOnce sync.Once
)

func mac() []byte {
	macOnce.Do(func() {
		ifaces, _ := net.Interfaces()
		for _, iface := range ifaces {
			if len(iface.HardwareAddr) >= 6 {
				copy(cachedMAC[:], iface.HardwareAddr[:6])
				hasMAC = true
				break
			}
		}
	})
	return cachedMAC[:]
}

// NewV2 generates a Version 2 UUID (DCE Security).
// It replaces the low 32 bits of the timestamp with a local identifier (UID/GID)
// and the lower 8 bits of the clock sequence with a domain identifier.
func NewV2(domain byte) UUID {
	u := NewV1()

	var id uint32
	switch domain {
	case 0:
		id = uint32(os.Getuid())
	case 1:
		id = uint32(os.Getgid())
	default:
		id = 0
	}

	binary.BigEndian.PutUint32(u[0:], id)
	u[6] = (u[6] & 0x0F) | 0x20 // Version 2
	u[9] = domain

	return u
}

// NewV3 generates a Version 3 UUID based on the MD5 hash of a namespace UUID and a name.
// Note: RFC 4122 recommends Version 5 (SHA-1) over Version 3 for new applications.
//
// https://www.ietf.org/rfc/rfc4122.html#section-4.3
// https://datatracker.ietf.org/doc/html/rfc9562#section-5.3-4
func NewV3(ns UUID, name string) UUID {
	return newHashUUID(md5.New(), ns, name, 0x30)
}

func newHashUUID(h hash.Hash, ns UUID, name string, version byte) UUID {
	var u UUID
	_, _ = h.Write(ns[:])
	_, _ = io.WriteString(h, name)
	sum := h.Sum(nil)
	copy(u[:], sum[:16])

	u[6] = (u[6] &^ 0xF0) | version
	u[8] = (u[8] &^ 0xC0) | 0x80

	return u
}

var pool = sync.Pool{
	New: func() any {
		buf := make([]byte, 4096)
		_, _ = io.ReadFull(cryptorand.Reader, buf)
		return &randBuf{buf: buf}
	},
}

type randBuf struct {
	buf []byte
	pos int
}

func (r *randBuf) next(n int) []byte {
	// read new 4096 bytes
	if r.pos+n > len(r.buf) {
		_, _ = cryptorand.Read(r.buf)
		r.pos = 0
	}

	// use next 16 bytes of buf
	out := r.buf[r.pos : r.pos+n]
	r.pos += n

	return out
}

// NewV4Pool generates a Version 4 UUID using a synchronized buffer pool of cryptographically
// secure random bytes. This drastically reduces system calls and allocations,
// making it significantly faster than standard NewV4 under high concurrency.
func NewV4Pool() UUID {
	r := pool.Get().(*randBuf)
	defer pool.Put(r)

	var u UUID
	copy(u[:], r.next(16))

	u[6] = (u[6] & 0x0F) | 0x40 // Version 4
	u[8] = (u[8] & 0x3F) | 0x80 // Variant RFC 4122

	return u
}

// NewV4 generates a Version 4 UUID using cryptographically secure random numbers (CSPRNG).
//
// Layout:
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                           random_a                            |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|          random_a             |  ver  |       random_b        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|var|                        random_c                           |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                            random_c                           |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func NewV4() UUID {
	var u UUID
	_, _ = cryptorand.Read(u[:])

	u[6] = (u[6] & 0x0F) | 0x40 // Version 4
	u[8] = (u[8] & 0x3F) | 0x80 // Variant RFC 4122

	return u
}

// NewV4Fast generates a Version 4 UUID using math/rand/v2 as a fast PRNG (ChaCha8).
//
// WARNING: Not suitable for security-sensitive identifiers or cryptographic secrets.
// Use NewV4 or NewV4Pool for externally visible IDs.
func NewV4Fast() UUID {
	var u UUID

	binary.LittleEndian.PutUint64(u[0:8], mathrand.Uint64())
	binary.LittleEndian.PutUint64(u[8:16], mathrand.Uint64())

	u[6] = (u[6] & 0x0F) | 0x40 // Version 4
	u[8] = (u[8] & 0x3F) | 0x80 // Variant RFC 4122

	return u
}

// NewV5 generates a Version 5 UUID based on the SHA-1 hash of a namespace UUID and a name.
// It is the preferred method for generating name-based UUIDs over Version 3.
//
// Layout (RFC 9562):
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                           sha1_high                           |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|         sha1_high             |  ver  |      sha1_mid         |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|var|                       sha1_low                            |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                           sha1_low                            |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func NewV5(namespace UUID, name string) UUID {
	h := sha1.New()
	_, _ = h.Write(namespace[:])
	_, _ = io.WriteString(h, name)
	sum := h.Sum(nil)

	var uuid UUID
	copy(uuid[:], sum[:16])

	uuid[6] = (uuid[6] & 0x0F) | 0x50 // Version 5
	uuid[8] = (uuid[8] & 0x3F) | 0x80 // Variant

	return uuid
}

var (
	timeMu sync.Mutex
)

// NewV6 generates a Version 6 UUID, a field-compatible version of UUIDv1 ordered by time.
// It features improved database locality over Version 1.
//
// Layout (RFC 9562):
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                           time_high                           |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|           time_mid            |  ver  |       time_low        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|var|         clock_seq         |             node              |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                              node                             |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func NewV6() UUID {
	var u UUID

	onceClockSeq.Do(initClockSequence)
	now := timestampUUID()

	timeMu.Lock()
	if now <= lastTime {
		clockSeq = (clockSeq + 1) & 0x3FFF
	}
	lastTime = now
	seq := clockSeq
	timeMu.Unlock()

	binary.BigEndian.PutUint32(u[0:], uint32(now>>28))
	binary.BigEndian.PutUint16(u[4:], uint16(now>>12))

	u[6] = 0x60 | byte((now>>8)&0x0F)
	u[7] = byte(now)

	u[8] = byte(seq >> 8)
	u[9] = byte(seq)
	u[8] = (u[8] &^ 0xC0) | 0x80

	node := mac()
	if hasMAC {
		copy(u[10:], node)
	} else {
		_, _ = cryptorand.Read(u[10:])
		u[10] |= 0x01 // multicast bit
	}

	return u
}

const uuidEpochStart = 122192928000000000

func timestampUUID() uint64 {
	now := time.Now().UTC()
	return uint64(now.UnixNano()/100) + uuidEpochStart
}

// NewV7 generates a Version 7 UUID using a Unix Epoch timestamp (ms) and a cryptographically
// secure random number (CSPRNG). It guarantees time-ordering and is ideal for database primary keys.
// Includes lock-free atomics for sub-millisecond sequencing (RFC 9562 Method 1).
//
// Layout (RFC 9562):
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                           unix_ts_ms                          |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|          unix_ts_ms           |  ver  |       rand_a          |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|var|                        rand_b                             |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                            rand_b                             |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func NewV7() UUID {
	ms, seq := getV7State()
	var u UUID

	u[0] = byte(ms >> 40)
	u[1] = byte(ms >> 32)
	u[2] = byte(ms >> 24)
	u[3] = byte(ms >> 16)
	u[4] = byte(ms >> 8)
	u[5] = byte(ms)

	u[6] = 0x70 | byte(seq>>8)
	u[7] = byte(seq)

	_, _ = cryptorand.Read(u[8:16])
	u[8] = (u[8] & 0x3F) | 0x80

	return u
}

// NewV7Fast is identical to NewV7 but uses math/rand/v2 (ChaCha8) for the rand_b field.
//
// WARNING: This provides a significant performance boost but sacrifices cryptographic security.
// Use only for internal application IDs where strict unguessability is not required.
func NewV7Fast() UUID {
	ms, seq := getV7State()
	var u UUID

	u[0] = byte(ms >> 40)
	u[1] = byte(ms >> 32)
	u[2] = byte(ms >> 24)
	u[3] = byte(ms >> 16)
	u[4] = byte(ms >> 8)
	u[5] = byte(ms)

	u[6] = 0x70 | byte(seq>>8)
	u[7] = byte(seq)

	binary.LittleEndian.PutUint64(u[8:16], mathrand.Uint64())
	u[8] = (u[8] & 0x3F) | 0x80

	return u
}

var v7state atomic.Uint64

func getV7State() (uint64, uint16) {
	for {
		curr := v7state.Load()
		now := uint64(time.Now().UnixMilli())
		currMs := curr >> 12

		var next uint64
		if now > currMs {
			next = now << 12
		} else {
			next = curr + 1
		}

		if v7state.CompareAndSwap(curr, next) {
			return next >> 12, uint16(next & 0xFFF)
		}

		runtime.Gosched()
	}
}
