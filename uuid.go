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
	"sync"
	"time"
	_ "unsafe"
)

type UUID [16]byte

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

func NewV1() UUID {
	onceClockSeq.Do(initClockSequence)

	var u UUID

	// 100-ns interval since 00:00:00:00 1582 year
	now := uint64(time.Now().UnixNano()/100) + mask

	// Update sequence if clock moved backwards
	if now <= lastTime {
		clockSeq = (clockSeq + 1) & 0x3FFF // 14 bit
	}
	lastTime = now

	// time_low
	binary.BigEndian.PutUint32(u[0:], uint32(now&0xFFFFFFFF))
	// time_mid
	binary.BigEndian.PutUint16(u[4:], uint16((now>>32)&0xFFFF))
	// time_hi_and_version (top 12 bits time, bottom 4 bits version)
	timeHi := uint16((now >> 48) & 0x0FFF)
	timeHi |= 1 << 12 // Version 1
	binary.BigEndian.PutUint16(u[6:], timeHi)

	// Clock sequence
	u[8] = byte(clockSeq >> 8)
	u[9] = byte(clockSeq)
	u[8] = (u[8] &^ 0xC0) | 0x80 // Variant RFC 4122

	// Node
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

func NewV3(ns UUID, name string) UUID {
	return newHashUUID(md5.New(), ns, name, 0x30)
}

func newHashUUID(h hash.Hash, ns UUID, name string, version byte) UUID {
	var u UUID
	_, _ = h.Write(ns[:])
	_, _ = h.Write([]byte(name))
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
		_, _ = io.ReadFull(cryptorand.Reader, r.buf)
		r.pos = 0
	}

	// use next 16 bytes of buf
	out := r.buf[r.pos : r.pos+n]
	r.pos += n

	return out
}

// NewV4Pool using sync.Pool to store 4096 rand bytes.
// Every call get next 16 bytes from pool.
// Faster than NewV4.
func NewV4Pool() UUID {
	r := pool.Get().(*randBuf)
	defer pool.Put(r)

	var u UUID
	copy(u[:], r.next(16))

	u[6] = (u[6] & 0x0F) | 0x40 // Version 4
	u[8] = (u[8] & 0x3F) | 0x80 // Variant RFC 4122

	return u
}

func NewV4() UUID {
	var u UUID
	_, _ = cryptorand.Read(u[:])

	u[6] = (u[6] & 0x0F) | 0x40 // Version 4
	u[8] = (u[8] & 0x3F) | 0x80 // Variant RFC 4122

	return u
}

func NewV4Fast() UUID {
	var u UUID

	binary.LittleEndian.PutUint64(u[0:8], mathrand.Uint64())
	binary.LittleEndian.PutUint64(u[8:16], mathrand.Uint64())

	u[6] = (u[6] & 0x0F) | 0x40 // Version 4
	u[8] = (u[8] & 0x3F) | 0x80 // Variant RFC 4122

	return u
}

func NewV5(namespace UUID, name string) UUID {
	h := sha1.New()
	_, _ = h.Write(namespace[:])
	_, _ = h.Write([]byte(name))
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

func NewV6() UUID {
	var u UUID

	onceClockSeq.Do(initClockSequence)

	now := timestampUUID()

	timeMu.Lock()
	if now <= lastTime {
		clockSeq = (clockSeq + 1) & 0x3FFF
	}
	lastTime = now
	timeMu.Unlock()

	binary.BigEndian.PutUint16(u[0:], uint16(now>>48))        // time_high
	binary.BigEndian.PutUint16(u[2:], uint16(now>>32))        // time_mid
	binary.BigEndian.PutUint16(u[4:], uint16(now>>16)&0x0FFF) // time_low
	u[6] &= 0x0F
	u[6] |= 0x60 // Version 6

	u[7] = byte(now >> 8)
	u[8] = byte(clockSeq >> 8)
	u[9] = byte(clockSeq)
	u[8] = (u[8] &^ 0xC0) | 0x80 // Variant RFC 4122

	node := mac()
	if hasMAC {
		copy(u[10:], node)
	} else {
		_, _ = cryptorand.Read(u[10:])
		u[10] |= 0x01 // multicast bit
	}

	return u
}

// Difference between Unix epoch and UUID epoch (15 Oct 1582): ~122192928000000000
const uuidEpochStart = 122192928000000000

// timestampUUID returns 60-bit timestamp as per UUID epoch (100ns intervals since 1582-10-15)
func timestampUUID() uint64 {
	now := time.Now().UTC()
	return uint64(now.UnixNano()/100) + uuidEpochStart
}

func NewV7() UUID {
	var u UUID

	milli, seq := getV7Time()

	// timestamp (48 bits)
	u[0] = byte(milli >> 40)
	u[1] = byte(milli >> 32)
	u[2] = byte(milli >> 24)
	u[3] = byte(milli >> 16)
	u[4] = byte(milli >> 8)
	u[5] = byte(milli)

	u[6] = 0x70 | byte(seq>>8) // version=7
	u[7] = byte(seq)

	var randBuf [8]byte
	_, _ = cryptorand.Read(randBuf[:])
	randBuf[0] = (randBuf[0] & 0x3F) | 0x80 // variant RFC4122 (10xxxxxx)
	copy(u[8:], randBuf[:])

	return u
}

// from google/uuid
var (
	lastV7Time int64
)

const nanoPerMilli = int64(time.Millisecond)

func getV7Time() (milli int64, seq int64) {
	timeMu.Lock()
	defer timeMu.Unlock()

	nano := time.Now().UnixNano()
	milli = nano / nanoPerMilli
	seq = (nano % nanoPerMilli) >> 8

	now := milli<<12 | seq
	if now <= lastV7Time {
		now = lastV7Time + 1
		milli = now >> 12
		seq = now & 0xFFF
	}
	lastV7Time = now
	return milli, seq
}
