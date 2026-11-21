package vault

import (
	"bytes"
	"cmp"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/hndrxc/hx/internal/secret"
)

// Vault image format v1 (all integers big-endian):
//
//	header:  magic[8] version:u16 kdf:u8 memKiB:u32 passes:u32 lanes:u8 salt[16] wrapNonce[24]
//	wrapped: XChaCha20-Poly1305(KEK, wrapNonce, DEK, aad=domainWrap||header)  [48]
//	count:   u32
//	records: count × { intLen:u8 integration scopeLen:u8 scope nonce[24] ctLen:u32 ct }
//	         strictly ascending by (integration, scope)
//	image:   imageNonce[24] tag[16] = XChaCha20-Poly1305(DEK, imageNonce, "", aad=domainImage||everything above)
//
// KEK = Argon2id(passphrase, salt, RFC 9106 second recommended profile). Only the exact
// v1 tuple is accepted, and it is checked before any key derivation runs.

const (
	formatVersion uint16 = 1
	kdfArgon2id   uint8  = 1

	argonMemoryKiB uint32 = 64 * 1024
	argonPasses    uint32 = 3
	argonLanes     uint8  = 4

	saltSize  = 16
	keySize   = chacha20poly1305.KeySize
	nonceSize = chacha20poly1305.NonceSizeX
	tagSize   = chacha20poly1305.Overhead

	headerSize  = 8 + 2 + 1 + 4 + 4 + 1 + saltSize + nonceSize
	wrappedSize = keySize + tagSize
	trailerSize = nonceSize + tagSize
	minImage    = headerSize + wrappedSize + 4 + trailerSize

	maxNameLen = 64
	maxRecords = 4096
	maxCTLen   = secret.MaxSize + tagSize

	// maxImage bounds the serialized vault image accepted by decodeEnvelope and produced by encode.
	maxImage = 16 << 20
)

var magic = [8]byte{'H', 'X', 'V', 'A', 'U', 'L', 'T', 0}

var (
	domainWrap   = []byte("hx/vault/v1/wrap\x00")
	domainRecord = []byte("hx/vault/v1/record\x00")
	domainImage  = []byte("hx/vault/v1/image\x00")
)

var (
	// ErrCorrupt reports a malformed, oversized, ambiguous or unsupported vault image.
	ErrCorrupt = errors.New("vault: corrupt image")
	// ErrAuthentication reports a wrong passphrase or tampered ciphertext.
	ErrAuthentication = errors.New("vault: authentication failed")

	errInvalidKey     = errors.New("vault: invalid integration or scope")
	errTooManyRecords = errors.New("vault: too many records")
	errImageTooLarge  = errors.New("vault: image exceeds maximum size")
	errInvalidDEK     = errors.New("vault: invalid data key")
	errNotSealed      = errors.New("vault: image not sealed")
)

// key addresses one record.
type key struct {
	integration secret.IntegrationID
	scope       secret.Scope
}

func validName(s string) bool {
	if len(s) == 0 || len(s) > maxNameLen || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func validKey(k key) bool {
	return validName(string(k.integration)) && validName(string(k.scope))
}

func compareKey(a, b key) int {
	if c := cmp.Compare(a.integration, b.integration); c != 0 {
		return c
	}
	return cmp.Compare(a.scope, b.scope)
}

// record holds one encrypted value. ct is never mutated after construction.
type record struct {
	nonce [nonceSize]byte
	ct    []byte
}

// envelope is the in-memory form of a vault image. It never holds plaintext.
type envelope struct {
	salt      [saltSize]byte
	wrapNonce [nonceSize]byte
	wrapped   [wrappedSize]byte
	records   map[key]record

	// sealed reports whether imageNonce/imageTag authenticate the current contents.
	sealed     bool
	imageNonce [nonceSize]byte
	imageTag   [tagSize]byte
}

func (e *envelope) clone() *envelope {
	c := *e
	c.records = make(map[key]record, len(e.records))
	for k, r := range e.records {
		c.records[k] = r
	}
	return &c
}

func randomFill(b []byte) error {
	_, err := rand.Read(b)
	return err
}

// newEnvelope creates an empty sealed vault with a fresh random data key wrapped under pass.
// The caller owns the returned DEK.
func newEnvelope(pass *secret.Value) (*envelope, *secret.Value, error) {
	raw := make([]byte, keySize)
	if err := randomFill(raw); err != nil {
		clear(raw)
		return nil, nil, err
	}
	dek, err := secret.FromBytes(raw) // zeroes raw
	if err != nil {
		return nil, nil, err
	}
	e := &envelope{records: map[key]record{}}
	if err := e.rewrap(dek, pass); err != nil {
		dek.Destroy()
		return nil, nil, err
	}
	if _, err := e.encode(dek); err != nil {
		dek.Destroy()
		return nil, nil, err
	}
	return e, dek, nil
}

func (e *envelope) appendHeader(b []byte) []byte {
	b = append(b, magic[:]...)
	b = binary.BigEndian.AppendUint16(b, formatVersion)
	b = append(b, kdfArgon2id)
	b = binary.BigEndian.AppendUint32(b, argonMemoryKiB)
	b = binary.BigEndian.AppendUint32(b, argonPasses)
	b = append(b, argonLanes)
	b = append(b, e.salt[:]...)
	return append(b, e.wrapNonce[:]...)
}

func (e *envelope) sortedKeys() []key {
	keys := make([]key, 0, len(e.records))
	for k := range e.records {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, compareKey)
	return keys
}

func recordSize(k key, r record) int {
	return 1 + len(k.integration) + 1 + len(k.scope) + nonceSize + 4 + len(r.ct)
}

func (e *envelope) imageSize() int {
	n := minImage
	for k, r := range e.records {
		n += recordSize(k, r)
	}
	return n
}

// body serializes everything authenticated by the image tag.
func (e *envelope) body() []byte {
	b := make([]byte, 0, e.imageSize())
	b = e.appendHeader(b)
	b = append(b, e.wrapped[:]...)
	b = binary.BigEndian.AppendUint32(b, u32(len(e.records)))
	for _, k := range e.sortedKeys() {
		r := e.records[k]
		b = append(b, u8(len(k.integration)))
		b = append(b, k.integration...)
		b = append(b, u8(len(k.scope)))
		b = append(b, k.scope...)
		b = append(b, r.nonce[:]...)
		b = binary.BigEndian.AppendUint32(b, u32(len(r.ct)))
		b = append(b, r.ct...)
	}
	return b
}

func recordAAD(k key) []byte {
	b := make([]byte, 0, len(domainRecord)+2+len(k.integration)+len(k.scope))
	b = append(b, domainRecord...)
	b = append(b, u8(len(k.integration)))
	b = append(b, k.integration...)
	b = append(b, u8(len(k.scope)))
	return append(b, k.scope...)
}

// u8 converts a length validated at key construction/decode to its v1 one-byte
// width. A violation is an internal invariant breach, never input-driven.
func u8(n int) byte {
	if n < 0 || n > math.MaxUint8 {
		panic(fmt.Sprintf("vault: length %d exceeds uint8 wire field", n))
	}
	return byte(n)
}

// u32 converts a length bounded by the image size limit to its v1 four-byte width.
func u32(n int) uint32 {
	if n < 0 || uint64(n) > math.MaxUint32 {
		panic(fmt.Sprintf("vault: length %d exceeds uint32 wire field", n))
	}
	return uint32(n)
}

func prefixed(domain, data []byte) []byte {
	b := make([]byte, 0, len(domain)+len(data))
	return append(append(b, domain...), data...)
}

// deriveKEK runs Argon2id with the fixed v1 profile. The caller must clear the result.
func deriveKEK(pass, salt []byte) []byte {
	return argon2.IDKey(pass, salt, argonPasses, argonMemoryKiB, argonLanes, keySize)
}

func withKEK(pass *secret.Value, salt []byte, fn func(kek []byte) error) error {
	return pass.Use(func(p []byte) error {
		kek := deriveKEK(p, salt)
		defer clear(kek)
		return fn(kek)
	})
}

func withDEK(dek *secret.Value, fn func(k []byte) error) error {
	return dek.Use(func(k []byte) error {
		if len(k) != keySize {
			return errInvalidDEK
		}
		return fn(k)
	})
}

type parser struct {
	b   []byte
	bad bool
}

func (p *parser) take(n int) []byte {
	if p.bad || n < 0 || n > len(p.b) {
		p.bad = true
		return nil
	}
	v := p.b[:n:n]
	p.b = p.b[n:]
	return v
}

func (p *parser) u8() uint8 {
	if v := p.take(1); v != nil {
		return v[0]
	}
	return 0
}

func (p *parser) u16() uint16 {
	if v := p.take(2); v != nil {
		return binary.BigEndian.Uint16(v)
	}
	return 0
}

func (p *parser) u32() uint32 {
	if v := p.take(4); v != nil {
		return binary.BigEndian.Uint32(v)
	}
	return 0
}

// decodeEnvelope strictly parses a v1 image. It performs no key derivation; the result is
// unauthenticated until unlock succeeds.
func decodeEnvelope(raw []byte) (*envelope, error) {
	if len(raw) < minImage || len(raw) > maxImage {
		return nil, ErrCorrupt
	}
	p := &parser{b: raw}
	if !bytes.Equal(p.take(len(magic)), magic[:]) ||
		p.u16() != formatVersion ||
		p.u8() != kdfArgon2id ||
		p.u32() != argonMemoryKiB ||
		p.u32() != argonPasses ||
		p.u8() != argonLanes || p.bad {
		return nil, ErrCorrupt
	}
	e := &envelope{}
	copy(e.salt[:], p.take(saltSize))
	copy(e.wrapNonce[:], p.take(nonceSize))
	copy(e.wrapped[:], p.take(wrappedSize))
	count := p.u32()
	if p.bad || count > maxRecords {
		return nil, ErrCorrupt
	}
	e.records = make(map[key]record, count)
	var prev key
	for i := uint32(0); i < count; i++ {
		var k key
		k.integration = secret.IntegrationID(p.take(int(p.u8())))
		k.scope = secret.Scope(p.take(int(p.u8())))
		var r record
		copy(r.nonce[:], p.take(nonceSize))
		n := p.u32()
		if p.bad || n < tagSize || n > maxCTLen {
			return nil, ErrCorrupt
		}
		r.ct = bytes.Clone(p.take(int(n)))
		if p.bad || !validKey(k) || (i > 0 && compareKey(prev, k) >= 0) {
			return nil, ErrCorrupt
		}
		e.records[k] = r
		prev = k
	}
	copy(e.imageNonce[:], p.take(nonceSize))
	copy(e.imageTag[:], p.take(tagSize))
	if p.bad || len(p.b) != 0 {
		return nil, ErrCorrupt
	}
	e.sealed = true
	return e, nil
}

// unlock derives the KEK, unwraps the DEK and verifies the entire image. The caller owns the DEK.
func (e *envelope) unlock(pass *secret.Value) (*secret.Value, error) {
	if !e.sealed {
		return nil, errNotSealed
	}
	raw := make([]byte, 0, keySize)
	defer clear(raw[:cap(raw)])
	header := e.appendHeader(nil)
	err := withKEK(pass, e.salt[:], func(kek []byte) error {
		aead, err := chacha20poly1305.NewX(kek)
		if err != nil {
			return err
		}
		if _, err := aead.Open(raw, e.wrapNonce[:], e.wrapped[:], prefixed(domainWrap, header)); err != nil {
			return ErrAuthentication
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	dek, err := secret.FromBytes(raw[:keySize]) // zeroes raw
	if err != nil {
		return nil, err
	}
	if err := e.verify(dek); err != nil {
		dek.Destroy()
		return nil, err
	}
	return dek, nil
}

func (e *envelope) verify(dek *secret.Value) error {
	aad := prefixed(domainImage, e.body())
	return withDEK(dek, func(k []byte) error {
		aead, err := chacha20poly1305.NewX(k)
		if err != nil {
			return err
		}
		sealed := make([]byte, 0, tagSize)
		sealed = append(sealed, e.imageTag[:]...)
		if _, err := aead.Open(nil, e.imageNonce[:], sealed, aad); err != nil {
			return ErrAuthentication
		}
		return nil
	})
}

// rewrap wraps dek under pass with fresh salt and nonce. The image must be re-encoded afterwards.
func (e *envelope) rewrap(dek, pass *secret.Value) error {
	var salt [saltSize]byte
	var nonce [nonceSize]byte
	if err := randomFill(salt[:]); err != nil {
		return err
	}
	if err := randomFill(nonce[:]); err != nil {
		return err
	}
	next := *e
	next.salt, next.wrapNonce = salt, nonce
	header := next.appendHeader(nil)
	var wrapped [wrappedSize]byte
	err := withDEK(dek, func(d []byte) error {
		return withKEK(pass, salt[:], func(kek []byte) error {
			aead, err := chacha20poly1305.NewX(kek)
			if err != nil {
				return err
			}
			aead.Seal(wrapped[:0], nonce[:], d, prefixed(domainWrap, header))
			return nil
		})
	})
	if err != nil {
		return err
	}
	e.salt, e.wrapNonce, e.wrapped = salt, nonce, wrapped
	e.sealed = false
	return nil
}

// rekey returns an unpublished copy of e whose records are re-encrypted, one at a time, under a
// fresh random DEK wrapped by newPass. e is unchanged. The new envelope is unsealed until the caller
// encodes it with the returned DEK, which the caller owns.
func (e *envelope) rekey(oldDEK, newPass *secret.Value) (*envelope, *secret.Value, error) {
	raw := make([]byte, keySize)
	if err := randomFill(raw); err != nil {
		clear(raw)
		return nil, nil, err
	}
	newDEK, err := secret.FromBytes(raw) // zeroes raw
	if err != nil {
		return nil, nil, err
	}
	next := &envelope{records: make(map[key]record, len(e.records))}
	err = withDEK(oldDEK, func(od []byte) error {
		oldAEAD, err := chacha20poly1305.NewX(od)
		if err != nil {
			return err
		}
		return withDEK(newDEK, func(nd []byte) error {
			newAEAD, err := chacha20poly1305.NewX(nd)
			if err != nil {
				return err
			}
			pt := make([]byte, 0, secret.MaxSize+tagSize)
			defer clear(pt[:cap(pt)])
			for k, r := range e.records {
				aad := recordAAD(k)
				dec, err := oldAEAD.Open(pt[:0], r.nonce[:], r.ct, aad)
				if err != nil {
					return ErrCorrupt
				}
				var nr record
				if err := randomFill(nr.nonce[:]); err != nil {
					clear(dec)
					return err
				}
				nr.ct = newAEAD.Seal(make([]byte, 0, len(dec)+tagSize), nr.nonce[:], dec, aad)
				clear(dec)
				next.records[k] = nr
			}
			return nil
		})
	})
	if err == nil {
		err = next.rewrap(newDEK, newPass)
	}
	if err != nil {
		newDEK.Destroy()
		return nil, nil, err
	}
	return next, newDEK, nil
}

// put encrypts value under k with a fresh nonce, replacing any existing record.
func (e *envelope) put(dek *secret.Value, k key, value *secret.Value) error {
	if !validKey(k) {
		return errInvalidKey
	}
	old, exists := e.records[k]
	if !exists && len(e.records) >= maxRecords {
		return errTooManyRecords
	}
	var r record
	if err := randomFill(r.nonce[:]); err != nil {
		return err
	}
	aad := recordAAD(k)
	err := withDEK(dek, func(d []byte) error {
		aead, err := chacha20poly1305.NewX(d)
		if err != nil {
			return err
		}
		return value.Use(func(pt []byte) error {
			if len(pt) > secret.MaxSize {
				return secret.ErrTooLarge
			}
			r.ct = aead.Seal(make([]byte, 0, len(pt)+tagSize), r.nonce[:], pt, aad)
			return nil
		})
	})
	if err != nil {
		return err
	}
	size := e.imageSize() + recordSize(k, r)
	if exists {
		size -= recordSize(k, old)
	}
	if size > maxImage {
		return errImageTooLarge
	}
	e.records[k] = r
	e.sealed = false
	return nil
}

func (e *envelope) remove(k key) error {
	if _, ok := e.records[k]; !ok {
		return secret.ErrNotFound
	}
	delete(e.records, k)
	e.sealed = false
	return nil
}

// open decrypts the record at k. The caller owns the returned Value.
func (e *envelope) open(dek *secret.Value, k key) (*secret.Value, error) {
	r, ok := e.records[k]
	if !ok {
		return nil, secret.ErrNotFound
	}
	var pt []byte
	err := withDEK(dek, func(d []byte) error {
		aead, err := chacha20poly1305.NewX(d)
		if err != nil {
			return err
		}
		pt, err = aead.Open(make([]byte, 0, len(r.ct)), r.nonce[:], r.ct, recordAAD(k))
		if err != nil {
			// The DEK and image were authenticated at unlock, so a failing record means
			// the in-memory state is corrupt rather than a wrong passphrase.
			clear(pt[:cap(pt)])
			return ErrCorrupt
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return secret.FromBytes(pt) // zeroes pt
}

// encode seals the current contents with a fresh image nonce and returns the serialized image.
func (e *envelope) encode(dek *secret.Value) ([]byte, error) {
	body := e.body()
	if len(body)+trailerSize > maxImage {
		return nil, errImageTooLarge
	}
	var nonce [nonceSize]byte
	if err := randomFill(nonce[:]); err != nil {
		return nil, err
	}
	aad := prefixed(domainImage, body)
	var tag [tagSize]byte
	err := withDEK(dek, func(d []byte) error {
		aead, err := chacha20poly1305.NewX(d)
		if err != nil {
			return err
		}
		aead.Seal(tag[:0], nonce[:], nil, aad)
		return nil
	})
	if err != nil {
		return nil, err
	}
	e.imageNonce, e.imageTag, e.sealed = nonce, tag, true
	out := append(body, nonce[:]...)
	return append(out, tag[:]...), nil
}
