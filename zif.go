package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/bits"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	magic     = "E27\x03"
	saltLen   = 16
	chunkSize = 64 * 1024
	tagLen    = 16

	kdfMemLog = 19
	kdfBlocks = 1 << kdfMemLog
	kdfMinLog = 14
	kdfMaxLog = 24

	headerLen = len(magic) + 1 + saltLen

	vaultExt   = ".zif"
	keyExt     = ".zifkey.txt"
	keyBegin   = "-----BEGIN ZIF KEY-----"
	keyEnd     = "-----END ZIF KEY-----"
	keyVersion = "3"

	numRotors     = 27
	tableLen      = 256
	keyPayloadLen = (numRotors+1)*tableLen + 2*numRotors

	rateBytes = 32

	sboxMaxDU = 10
	sboxMinNL = 94
)

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

var mdsRow = [8]byte{1, 1, 4, 1, 8, 5, 2, 9}

func gmul(a, b byte) byte {
	var p byte
	for b != 0 {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1d
		}
		b >>= 1
	}
	return p
}

func sboxQuality(s *[tableLen]byte) (du, nl int) {
	for dx := 1; dx < tableLen; dx++ {
		var cnt [tableLen]int
		for x := 0; x < tableLen; x++ {
			cnt[s[x]^s[x^dx]]++
		}
		for _, c := range cnt {
			if c > du {
				du = c
			}
		}
	}
	maxW := 0
	var w [tableLen]int
	for b := 1; b < tableLen; b++ {
		for x := 0; x < tableLen; x++ {
			if bits.OnesCount8(s[x]&byte(b))&1 == 1 {
				w[x] = -1
			} else {
				w[x] = 1
			}
		}
		for h := 1; h < tableLen; h <<= 1 {
			for i := 0; i < tableLen; i += h << 1 {
				for j := i; j < i+h; j++ {
					a, c := w[j], w[j+h]
					w[j], w[j+h] = a+c, a-c
				}
			}
		}
		for _, v := range w {
			if v < 0 {
				v = -v
			}
			if v > maxW {
				maxW = v
			}
		}
	}
	return du, 128 - maxW/2
}

func effectiveSbox(rot []byte, offset byte) [tableLen]byte {
	var t [tableLen]byte
	for x := 0; x < tableLen; x++ {
		t[x] = rot[byte(x)+offset] - offset
	}
	return t
}

func goodSbox(s *[tableLen]byte) bool {
	du, nl := sboxQuality(s)
	return du <= sboxMaxDU && nl >= sboxMinNL
}

type keyConfig struct {
	payload []byte
	eng     *enigma
}

func newKeyConfig(payload []byte) *keyConfig { return &keyConfig{payload: payload} }

func (k *keyConfig) rotor(r int) []byte { return k.payload[(r+1)*tableLen : (r+2)*tableLen] }
func (k *keyConfig) offset(r int) byte  { return k.payload[(numRotors+1)*tableLen+r] }
func (k *keyConfig) step(r int) byte    { return k.payload[(numRotors+1)*tableLen+numRotors+r] }

func (k *keyConfig) engine() *enigma {
	if k.eng == nil {
		k.eng = k.newEnigma()
	}
	return k.eng
}

func randBelow(n int) (int, error) {
	limit := 256 - 256%n
	var b [1]byte
	for {
		if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
			return 0, err
		}
		if int(b[0]) < limit {
			return int(b[0]) % n, nil
		}
	}
}

func randomPerm(p []byte) error {
	for i := range p {
		p[i] = byte(i)
	}
	for j := tableLen - 1; j >= 1; j-- {
		k, err := randBelow(j + 1)
		if err != nil {
			return err
		}
		p[j], p[k] = p[k], p[j]
	}
	return nil
}

func generateKey() (*keyConfig, error) {
	payload := make([]byte, keyPayloadLen)
	if err := randomPerm(payload[:tableLen]); err != nil {
		return nil, err
	}
	k := newKeyConfig(payload)
	base := (numRotors + 1) * tableLen
	for r := 0; r < numRotors; r++ {
		rot := k.rotor(r)
		for {
			if err := randomPerm(rot); err != nil {
				return nil, err
			}
			o, err := randBelow(256)
			if err != nil {
				return nil, err
			}
			payload[base+r] = byte(o)
			s := effectiveSbox(rot, byte(o))
			if goodSbox(&s) {
				break
			}
		}
		s, err := randBelow(128)
		if err != nil {
			return nil, err
		}
		payload[base+numRotors+r] = byte(s*2 + 1)
	}
	return k, nil
}

func (k *keyConfig) checksum() string {
	return hex.EncodeToString(k.engine().hash("E27-key-checksum", k.payload, 4))
}

func (k *keyConfig) text() string {
	var sb strings.Builder
	sb.WriteString(keyBegin + "\n")
	sb.WriteString("Version: " + keyVersion + "\n")
	enc := base64.StdEncoding.EncodeToString(k.payload)
	for len(enc) > 0 {
		n := 64
		if len(enc) < n {
			n = len(enc)
		}
		sb.WriteString(enc[:n] + "\n")
		enc = enc[n:]
	}
	sb.WriteString("Checksum: " + k.checksum() + "\n")
	sb.WriteString(keyEnd + "\n")
	return sb.String()
}

func isPermutation(p []byte) bool {
	var seen [256]bool
	for _, v := range p {
		if seen[v] {
			return false
		}
		seen[v] = true
	}
	return len(p) == 256
}

func parseKey(text string) (*keyConfig, error) {
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	in, ended := false, false
	var b64 strings.Builder
	checksum := ""
loop:
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "":
		case line == keyBegin:
			in = true
		case !in:
		case line == keyEnd:
			ended = true
			break loop
		case strings.HasPrefix(line, "Version:"):
			if strings.TrimSpace(strings.TrimPrefix(line, "Version:")) != keyVersion {
				return nil, errors.New("unsupported key version")
			}
		case strings.HasPrefix(line, "Checksum:"):
			checksum = strings.TrimSpace(strings.TrimPrefix(line, "Checksum:"))
		default:
			b64.WriteString(strings.Join(strings.Fields(line), ""))
		}
	}
	if !in {
		return nil, errors.New("key block not found (missing BEGIN line)")
	}
	if !ended {
		return nil, errors.New("key block incomplete (missing END line)")
	}
	payload, err := base64.StdEncoding.DecodeString(b64.String())
	if err != nil {
		return nil, errors.New("key is corrupted (bad base64, check the copy/paste)")
	}
	if len(payload) != keyPayloadLen {
		return nil, errors.New("key is corrupted (wrong length, check the copy/paste)")
	}
	k := newKeyConfig(payload)
	if checksum == "" || !strings.EqualFold(checksum, k.checksum()) {
		return nil, errors.New("key is corrupted (checksum mismatch, check the copy/paste)")
	}
	for t := 0; t <= numRotors; t++ {
		if !isPermutation(payload[t*tableLen : (t+1)*tableLen]) {
			return nil, errors.New("key is invalid (table is not a permutation)")
		}
	}
	for r := 0; r < numRotors; r++ {
		if k.step(r)%2 == 0 {
			return nil, errors.New("key is invalid (even step value)")
		}
		s := effectiveSbox(k.rotor(r), k.offset(r))
		if !goodSbox(&s) {
			return nil, errors.New("key is invalid (weak rotor)")
		}
	}
	return k, nil
}

func loadKeyFile(path string) (*keyConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read key file: %v", err)
	}
	k, err := parseKey(string(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	return k, nil
}

func pasteKey() (*keyConfig, error) {
	fmt.Fprintln(os.Stderr, "No -k given. Paste the key block (BEGIN ... END), then press Enter:")
	var sb strings.Builder
	for {
		line, err := stdin.ReadString('\n')
		sb.WriteString(line)
		if strings.TrimSpace(line) == keyEnd || err != nil {
			break
		}
	}
	return parseKey(sb.String())
}

type pstate [8]uint64

func (s *pstate) getByte(n int) byte { return byte(s[n>>3] >> (8 * uint(n&7))) }
func (s *pstate) xorByte(n int, b byte) {
	s[n>>3] ^= uint64(b) << (8 * uint(n&7))
}
func (s *pstate) setByte(n int, b byte) {
	sh := 8 * uint(n&7)
	s[n>>3] = s[n>>3]&^(0xff<<sh) | uint64(b)<<sh
}

type enigma struct {
	plug [tableLen]byte

	t  [numRotors][8][tableLen]uint64
	rc [numRotors][8]uint64
}

func (k *keyConfig) newEnigma() *enigma {
	e := &enigma{}
	copy(e.plug[:], k.payload[:tableLen])
	for r := 0; r < numRotors; r++ {
		off, step := k.offset(r), k.step(r)
		s := effectiveSbox(k.rotor(r), off)
		for c := 0; c < 8; c++ {
			for x := 0; x < tableLen; x++ {
				var v uint64
				for j := 0; j < 8; j++ {
					v |= uint64(gmul(s[x], mdsRow[(j-c)&7])) << (8 * uint(j))
				}
				e.t[r][c][x] = v
			}
		}

		for i := 0; i < 8; i++ {
			var v uint64
			for j := 0; j < 8; j++ {
				v |= uint64(off+step*byte(8*i+j+1)) << (8 * uint(j))
			}
			e.rc[r][i] = v
		}
	}
	return e
}

func (e *enigma) plugLayer(s *pstate) {
	for i := 0; i < 8; i++ {
		w := s[i]
		s[i] = uint64(e.plug[byte(w)]) |
			uint64(e.plug[byte(w>>8)])<<8 |
			uint64(e.plug[byte(w>>16)])<<16 |
			uint64(e.plug[byte(w>>24)])<<24 |
			uint64(e.plug[byte(w>>32)])<<32 |
			uint64(e.plug[byte(w>>40)])<<40 |
			uint64(e.plug[byte(w>>48)])<<48 |
			uint64(e.plug[byte(w>>56)])<<56
	}
}

func (e *enigma) permute(s *pstate) {
	e.plugLayer(s)
	for r := 0; r < numRotors; r++ {
		t := &e.t[r]
		rc := &e.rc[r]
		var n pstate
		for i := 0; i < 8; i++ {
			n[i] = t[0][byte(s[i])] ^
				t[1][byte(s[(i+7)&7]>>8)] ^
				t[2][byte(s[(i+6)&7]>>16)] ^
				t[3][byte(s[(i+5)&7]>>24)] ^
				t[4][byte(s[(i+4)&7]>>32)] ^
				t[5][byte(s[(i+3)&7]>>40)] ^
				t[6][byte(s[(i+2)&7]>>48)] ^
				t[7][byte(s[(i+1)&7]>>56)] ^
				rc[i]
		}
		*s = n
	}
	e.plugLayer(s)
}

func (e *enigma) absorb(s *pstate, msg []byte) {
	for len(msg) >= rateBytes {
		for w := 0; w < 4; w++ {
			s[w] ^= binary.LittleEndian.Uint64(msg[8*w:])
		}
		e.permute(s)
		msg = msg[rateBytes:]
	}
	for j, b := range msg {
		s.xorByte(j, b)
	}
	s.xorByte(len(msg), 0x01)
	s.xorByte(rateBytes-1, 0x80)
	e.permute(s)
}

func (e *enigma) hash(label string, data []byte, n int) []byte {
	var s pstate
	msg := append([]byte(label), data...)
	e.absorb(&s, msg)
	out := make([]byte, 32)
	for w := 0; w < 4; w++ {
		binary.LittleEndian.PutUint64(out[8*w:], s[w])
	}
	return out[:n]
}

func (e *enigma) mix(s *pstate) {
	t := *s
	e.permute(s)
	for w := range s {
		s[w] ^= t[w]
	}
}

func (e *enigma) deriveKey(password, salt []byte, memLog uint8) pstate {
	blocks := 1 << memLog
	msg := make([]byte, 0, 32+len(salt)+len(password))
	msg = append(msg, "E27-KDF/2\x00"...)
	msg = append(msg, salt...)
	msg = append(msg, memLog)
	msg = binary.BigEndian.AppendUint32(msg, uint32(len(password)))
	msg = append(msg, password...)
	var s pstate
	e.absorb(&s, msg)
	wipe(msg)

	v := make([]pstate, blocks)
	for i := range v {
		v[i] = s
		e.mix(&s)
	}
	for i := 0; i < blocks; i++ {
		j := int(s[0] & uint64(blocks-1))
		for w := range s {
			s[w] ^= v[j][w]
		}
		e.mix(&s)
	}
	for i := range v {
		v[i] = pstate{}
	}
	return s
}

func (e *enigma) chunkState(K *pstate, ctr uint64, final byte) pstate {
	s := *K
	s[4] ^= ctr
	s[5] ^= uint64(final) | 0x100
	e.permute(&s)
	return s
}

func (e *enigma) crypt(s *pstate, in, out []byte, decrypt bool) {
	n := len(in)
	i := 0
	for ; n-i >= rateBytes; i += rateBytes {
		for w := 0; w < 4; w++ {
			x := binary.LittleEndian.Uint64(in[i+8*w:])
			y := x ^ s[w]
			binary.LittleEndian.PutUint64(out[i+8*w:], y)
			if decrypt {
				s[w] = x
			} else {
				s[w] = y
			}
		}
		e.permute(s)
	}
	m := n - i
	for j := 0; j < m; j++ {
		x := in[i+j]
		y := x ^ s.getByte(j)
		out[i+j] = y
		if decrypt {
			s.setByte(j, x)
		} else {
			s.setByte(j, y)
		}
	}
	s.xorByte(m, 0x01)
	s.xorByte(rateBytes-1, 0x80)
	e.permute(s)
}

func tagOf(s *pstate) (t [tagLen]byte) {
	binary.LittleEndian.PutUint64(t[0:], s[0])
	binary.LittleEndian.PutUint64(t[8:], s[1])
	return
}

func (e *enigma) seal(K *pstate, ctr uint64, final byte, data []byte) [tagLen]byte {
	s := e.chunkState(K, ctr, final)
	e.crypt(&s, data, data, false)
	return tagOf(&s)
}

func (e *enigma) open(K *pstate, ctr uint64, final byte, data, tag []byte) bool {
	s := e.chunkState(K, ctr, final)
	e.crypt(&s, data, data, true)
	want := tagOf(&s)
	return subtle.ConstantTimeCompare(want[:], tag) == 1
}

type encWriter struct {
	w   io.Writer
	eng *enigma
	K   pstate
	ctr uint64
	buf []byte
}

func newEncWriter(w io.Writer, password []byte, key *keyConfig) (*encWriter, error) {
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	eng := key.engine()
	K := eng.deriveKey(password, salt, kdfMemLog)
	header := append([]byte(magic), kdfMemLog)
	header = append(header, salt...)
	if _, err := w.Write(header); err != nil {
		return nil, err
	}
	return &encWriter{w: w, eng: eng, K: K, buf: make([]byte, 0, chunkSize*2)}, nil
}

func (e *encWriter) Write(p []byte) (int, error) {
	e.buf = append(e.buf, p...)
	for len(e.buf) > chunkSize {
		if err := e.seal(e.buf[:chunkSize], 0); err != nil {
			return 0, err
		}
		e.buf = e.buf[:copy(e.buf, e.buf[chunkSize:])]
	}
	return len(p), nil
}

func (e *encWriter) Close() error {
	err := e.seal(e.buf, 1)
	e.K = pstate{}
	return err
}

func (e *encWriter) seal(plain []byte, final byte) error {
	tag := e.eng.seal(&e.K, e.ctr, final, plain)
	e.ctr++
	var hdr [5]byte
	hdr[0] = final
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(plain)))
	if _, err := e.w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := e.w.Write(plain); err != nil {
		return err
	}
	_, err := e.w.Write(tag[:])
	return err
}

type vaultReader struct {
	f      *os.File
	eng    *enigma
	K      pstate
	base   int64
	chunks int
	last   int
	size   int64
	cached int
	cur    int
	plain  []byte
	ct     []byte
}

const recordOverhead = 5 + tagLen

func openVault(path string, password []byte, key *keyConfig) (*vaultReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	var nv *vaultReader
	ok := false
	defer func() {
		if ok {
			return
		}
		if nv != nil {
			nv.Close()
		} else {
			f.Close()
		}
	}()

	head := make([]byte, headerLen)
	if _, err := io.ReadFull(f, head); err != nil {
		return nil, errors.New("file too short, not a zif vault")
	}
	if string(head[:len(magic)]) != magic {
		if string(head[:3]) == "E27" && (head[3] == 1 || head[3] == 2) {
			return nil, fmt.Errorf("vault was made by an older zif version (format E27 v%d); open it with that version", head[3])
		}
		return nil, errors.New("not a zif vault (unknown format)")
	}
	memLog := head[len(magic)]
	if memLog < kdfMinLog || memLog > kdfMaxLog {
		return nil, errors.New("vault header is invalid (unsupported KDF memory setting)")
	}
	salt := head[len(magic)+1:]
	eng := key.engine()
	nv = &vaultReader{
		f: f, eng: eng, base: int64(len(head)), cached: -1,
		plain: make([]byte, chunkSize), ct: make([]byte, chunkSize),
	}
	nv.K = eng.deriveKey(password, salt, memLog)
	if err := nv.verify(); err != nil {
		return nil, err
	}
	ok = true
	return nv, nil
}

func (v *vaultReader) verify() error {
	if _, err := v.f.Seek(v.base, io.SeekStart); err != nil {
		return err
	}
	r := bufio.NewReaderSize(v.f, 1<<16)
	var ctr uint64
	for {
		var hdr [5]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return errors.New("vault is truncated")
		}
		final := hdr[0]
		n32 := binary.BigEndian.Uint32(hdr[1:])
		if final > 1 || n32 > chunkSize || (final == 0 && n32 != chunkSize) {
			return errors.New("vault is corrupted")
		}
		n := int(n32)
		ct := v.ct[:n]
		if _, err := io.ReadFull(r, ct); err != nil {
			return errors.New("vault is truncated")
		}
		var tag [tagLen]byte
		if _, err := io.ReadFull(r, tag[:]); err != nil {
			return errors.New("vault is truncated")
		}
		ok := v.eng.open(&v.K, ctr, final, ct, tag[:])
		wipe(ct)
		if !ok {
			return errors.New("wrong password, wrong key, or corrupted vault")
		}
		ctr++
		if final == 1 {
			v.last = n
			break
		}
	}
	if _, err := r.ReadByte(); err != io.EOF {
		return errors.New("unexpected data after end of vault")
	}
	v.chunks = int(ctr)
	v.size = int64(v.chunks-1)*chunkSize + int64(v.last)
	return nil
}

func (v *vaultReader) load(idx int) error {
	if idx == v.cached {
		return nil
	}
	v.cached = -1
	changed := errors.New("vault changed or became unreadable while extracting")
	off := v.base + int64(idx)*(chunkSize+recordOverhead)
	final, n := byte(0), chunkSize
	if idx == v.chunks-1 {
		final, n = 1, v.last
	}
	var hdr [5]byte
	if _, err := v.f.ReadAt(hdr[:], off); err != nil {
		return changed
	}
	if hdr[0] != final || int(binary.BigEndian.Uint32(hdr[1:])) != n {
		return changed
	}
	buf := v.plain[:n]
	if _, err := v.f.ReadAt(buf, off+5); err != nil {
		return changed
	}
	var tag [tagLen]byte
	if _, err := v.f.ReadAt(tag[:], off+5+int64(n)); err != nil {
		return changed
	}
	if !v.eng.open(&v.K, uint64(idx), final, buf, tag[:]) {
		wipe(buf)
		return changed
	}
	v.cached, v.cur = idx, n
	return nil
}

func (v *vaultReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	done := 0
	for done < len(p) {
		pos := off + int64(done)
		if pos >= v.size {
			return done, io.EOF
		}
		if err := v.load(int(pos / chunkSize)); err != nil {
			return done, err
		}
		done += copy(p[done:], v.plain[int(pos%chunkSize):v.cur])
	}
	return done, nil
}

func (v *vaultReader) Close() error {
	wipe(v.plain)
	wipe(v.ct)
	v.K = pstate{}
	return v.f.Close()
}

func gfInverseTable() (inv [256]byte) {
	for a := 1; a < 256; a++ {
		for b := 1; b < 256; b++ {
			if gmul(byte(a), byte(b)) == 1 {
				inv[a] = byte(b)
				break
			}
		}
	}
	return
}

func checkMDS() (ok bool, count int) {
	inv := gfInverseTable()
	var C [8][8]byte
	for k := 0; k < 8; k++ {
		for j := 0; j < 8; j++ {
			C[k][j] = mdsRow[(j-k)&7]
		}
	}
	nonSingular := func(m [][]byte) bool {
		n := len(m)
		for c := 0; c < n; c++ {
			p := -1
			for r := c; r < n; r++ {
				if m[r][c] != 0 {
					p = r
					break
				}
			}
			if p < 0 {
				return false
			}
			m[c], m[p] = m[p], m[c]
			iv := inv[m[c][c]]
			for r := c + 1; r < n; r++ {
				if m[r][c] == 0 {
					continue
				}
				f := gmul(m[r][c], iv)
				for k := c; k < n; k++ {
					m[r][k] ^= gmul(f, m[c][k])
				}
			}
		}
		return true
	}
	for rm := 1; rm < 256; rm++ {
		for cm := 1; cm < 256; cm++ {
			if bits.OnesCount(uint(rm)) != bits.OnesCount(uint(cm)) {
				continue
			}
			var rows, cols []int
			for i := 0; i < 8; i++ {
				if rm>>uint(i)&1 == 1 {
					rows = append(rows, i)
				}
				if cm>>uint(i)&1 == 1 {
					cols = append(cols, i)
				}
			}
			m := make([][]byte, len(rows))
			for a, ri := range rows {
				m[a] = make([]byte, len(cols))
				for b, ci := range cols {
					m[a][b] = C[ri][ci]
				}
			}
			count++
			if !nonSingular(m) {
				return false, count
			}
		}
	}
	return true, count
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	return b
}

func hamming(a, b *pstate) int {
	d := 0
	for i := range a {
		d += bits.OnesCount64(a[i] ^ b[i])
	}
	return d
}

func selfTest() error {
	fails := 0
	rep := func(pass bool, name, detail string) {
		st := "PASS"
		if !pass {
			st = "FAIL"
			fails++
		}
		fmt.Printf("  [%s] %s\n         %s\n", st, name, detail)
	}
	fmt.Println("E27 self-test (ZIF pure-Enigma cipher, 27 rotors)")
	fmt.Println("(sanity checks only; passing them is NOT a proof of security)")
	fmt.Println()

	ok, n := checkMDS()
	rep(ok, "diffusion matrix is MDS", fmt.Sprintf("%d square submatrices, all invertible (branch number 9)", n))

	t0 := time.Now()
	key, err := generateKey()
	if err != nil {
		return err
	}
	gen := time.Since(t0)
	worstDU, worstNL := 0, 999
	for r := 0; r < numRotors; r++ {
		s := effectiveSbox(key.rotor(r), key.offset(r))
		du, nl := sboxQuality(&s)
		if du > worstDU {
			worstDU = du
		}
		if nl < worstNL {
			worstNL = nl
		}
	}
	rep(worstDU <= sboxMaxDU && worstNL >= sboxMinNL, "rotor quality",
		fmt.Sprintf("%d rotors; worst differential uniformity %d, worst nonlinearity %d (AES: 4 / 112); key generated in %v",
			numRotors, worstDU, worstNL, gen.Round(time.Millisecond)))

	k2, perr := parseKey(key.text())
	same := perr == nil && bytes.Equal(k2.payload, key.payload)
	bad := strings.Replace(key.text(), "\n", "\nA", 3)
	_, berr := parseKey(bad)
	rep(same && berr != nil, "key file round-trip and typo detection",
		fmt.Sprintf("valid key parses back identical: %v; damaged key rejected: %v", same, berr != nil))

	eng := key.engine()

	const trials = 4000
	sum, minD, maxD := 0, 512, 0
	for i := 0; i < trials; i++ {
		var a pstate
		raw := randBytes(66)
		for j := 0; j < 64; j++ {
			a.setByte(j, raw[j])
		}
		b := a
		bit := (int(raw[64])<<8 | int(raw[65])) % 512
		b[bit>>6] ^= 1 << uint(bit&63)
		eng.permute(&a)
		eng.permute(&b)
		d := hamming(&a, &b)
		sum += d
		if d < minD {
			minD = d
		}
		if d > maxD {
			maxD = d
		}
	}
	mean := float64(sum) / trials
	rep(mean > 254 && mean < 258 && minD > 188 && maxD < 324, "avalanche of the permutation",
		fmt.Sprintf("flip 1 of 512 input bits -> %.1f of 512 output bits change on average (ideal 256), min %d, max %d, %d trials", mean, minD, maxD, trials))

	groups := numRotors / 4
	active := groups * 81
	rep(true, "design bound (heuristic estimate, not a proof)",
		fmt.Sprintf("branch number 9 => >= 81 active rotors per 4 rounds => >= %d over %d rounds; "+
			"each active rotor passes a differential with prob <= %d/256, so if rounds behave independently one differential trail has prob <= 2^-%d "+
			"(differential only: linear, integral and algebraic attacks are not covered, and generic attacks on the 512-bit state are far cheaper than this bound)",
			active, numRotors, sboxMaxDU, int(float64(active)*math.Log2(256.0/float64(sboxMaxDU)))))

	salt := randBytes(saltLen)
	t0 = time.Now()
	ka := eng.deriveKey([]byte("correct horse battery staple"), salt, kdfMemLog)
	kdfTime := time.Since(t0)
	kb := eng.deriveKey([]byte("correct horse battery stapld"), salt, kdfMemLog)
	salt2 := append([]byte(nil), salt...)
	salt2[0] ^= 1
	kc := eng.deriveKey([]byte("correct horse battery staple"), salt2, kdfMemLog)
	kd := eng.deriveKey([]byte("correct horse battery staple"), salt, kdfMemLog-1)
	dpw, dsalt, dmem := hamming(&ka, &kb), hamming(&ka, &kc), hamming(&ka, &kd)
	rep(dpw > 200 && dpw < 312 && dsalt > 200 && dsalt < 312 && dmem > 200 && dmem < 312, "key derivation sensitivity",
		fmt.Sprintf("1 password character -> %d/512 state bits differ; 1 salt bit -> %d/512; 1 memory-setting step -> %d/512 (ideal 256); memory-hard: %d MiB, %d permutation calls = %v per guess",
			dpw, dsalt, dmem, kdfBlocks*64>>20, 2*kdfBlocks, kdfTime.Round(time.Millisecond)))

	const total = 4 << 20
	data := make([]byte, total)
	for off, ctr := 0, uint64(0); off < total; off, ctr = off+chunkSize, ctr+1 {
		eng.seal(&ka, ctr, 0, data[off:off+chunkSize])
	}
	var freq [256]int
	ones := 0
	for _, b := range data {
		freq[b]++
		ones += bits.OnesCount8(b)
	}
	frac := float64(ones) / float64(total*8)
	chi := 0.0
	exp := float64(total) / 256
	for _, f := range freq {
		d := float64(f) - exp
		chi += d * d / exp
	}
	rep(frac > 0.4995 && frac < 0.5005 && chi > 180 && chi < 340, "keystream statistics",
		fmt.Sprintf("4 MiB of encrypted zeros: %.5f of bits are 1 (ideal 0.5), byte chi-square %.1f (255 dof, expect ~255 +-23)", frac, chi))

	msg := randBytes(100000)
	ref := append([]byte(nil), msg...)
	buf := append([]byte(nil), msg...)
	tag := eng.seal(&ka, 7, 1, buf)
	differs := !bytes.Equal(buf, ref)
	good := append([]byte(nil), buf...)
	roundTrip := eng.open(&ka, 7, 1, good, tag[:]) && bytes.Equal(good, ref)
	flip := func(mut func(ct []byte, tg []byte), ctr uint64, final byte, K *pstate) bool {
		ct := append([]byte(nil), buf...)
		tg := append([]byte(nil), tag[:]...)
		mut(ct, tg)
		return !eng.open(K, ctr, final, ct, tg)
	}
	noop := func(ct, tg []byte) {}
	rej := flip(func(ct, tg []byte) { ct[50000] ^= 1 }, 7, 1, &ka) &&
		flip(func(ct, tg []byte) { tg[3] ^= 0x10 }, 7, 1, &ka) &&
		flip(noop, 8, 1, &ka) &&
		flip(noop, 7, 0, &ka) &&
		flip(noop, 7, 1, &kb)
	short := append([]byte(nil), buf[:len(buf)-1]...)
	trunc := !eng.open(&ka, 7, 1, short, tag[:])
	rep(differs && roundTrip && rej && trunc, "authenticated encryption",
		fmt.Sprintf("round-trip ok: %v; rejected: flipped ciphertext bit, flipped tag bit, wrong chunk number, wrong final flag, wrong password, truncation: %v",
			roundTrip, rej && trunc))

	vok, vdetail := vaultSelfTest(key)
	rep(vok, "vault round-trip, streaming read and extraction safety", vdetail)

	speed := make([]byte, 16<<20)
	t0 = time.Now()
	for off, ctr := 0, uint64(0); off < len(speed); off, ctr = off+chunkSize, ctr+1 {
		eng.seal(&ka, ctr, 0, speed[off:off+chunkSize])
	}
	el := time.Since(t0).Seconds()
	fmt.Printf("\n  speed: %.1f MB/s encrypt+authenticate (single thread)\n", 16/el)

	fmt.Println()
	if fails > 0 {
		return fmt.Errorf("%d self-test check(s) failed", fails)
	}
	fmt.Println("All self-test checks passed.")
	return nil
}

func vaultSelfTest(key *keyConfig) (bool, string) {
	fail := func(f string, a ...any) (bool, string) { return false, fmt.Sprintf(f, a...) }
	tmp, err := os.MkdirTemp("", "zif-selftest-*")
	if err != nil {
		return fail("%v", err)
	}
	defer os.RemoveAll(tmp)

	src := filepath.Join(tmp, "src")
	files := map[string][]byte{
		"a.txt":          []byte("hello zif"),
		"empty.bin":      {},
		"sub/big.bin":    randBytes(3*chunkSize + 1234),
		"sub/deep/b.txt": randBytes(5000),
	}
	for name, data := range files {
		p := filepath.Join(src, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			return fail("%v", err)
		}
		if err := os.WriteFile(p, data, 0644); err != nil {
			return fail("%v", err)
		}
	}

	pw := []byte("self-test password")
	vault := filepath.Join(tmp, "t.zif")
	f, err := os.Create(vault)
	if err != nil {
		return fail("%v", err)
	}
	enc, err := newEncWriter(f, pw, key)
	if err != nil {
		return fail("%v", err)
	}
	if err := zipSource(src, enc); err != nil {
		return fail("zip: %v", err)
	}
	if err := enc.Close(); err != nil {
		return fail("%v", err)
	}
	f.Close()
	raw, err := os.ReadFile(vault)
	if err != nil {
		return fail("%v", err)
	}

	v, err := openVault(vault, pw, key)
	if err != nil {
		return fail("open: %v", err)
	}
	defer v.Close()
	out1 := filepath.Join(tmp, "out1")
	if err := unzipReader(v, v.size, out1); err != nil {
		return fail("extract: %v", err)
	}
	same := true
	for name, data := range files {
		got, err := os.ReadFile(filepath.Join(out1, "src", filepath.FromSlash(name)))
		if err != nil || !bytes.Equal(got, data) {
			same = false
		}
	}

	again := unzipReader(v, v.size, out1)
	got, _ := os.ReadFile(filepath.Join(out1, "src", "a.txt"))
	noOverwrite := again != nil && bytes.Equal(got, files["a.txt"])

	noSymlink := true
	if runtime.GOOS != "windows" {
		out2, outside := filepath.Join(tmp, "out2"), filepath.Join(tmp, "outside")
		os.MkdirAll(out2, 0755)
		os.MkdirAll(outside, 0755)
		if err := os.Symlink(outside, filepath.Join(out2, "src")); err == nil {
			e := unzipReader(v, v.size, out2)
			left, _ := os.ReadDir(outside)
			noSymlink = e != nil && len(left) == 0
		}
	}

	_, wrongPw := openVault(vault, []byte("wrong password"), key)
	bad := append([]byte(nil), raw...)
	bad[len(bad)/2] ^= 1
	badPath := filepath.Join(tmp, "bad.zif")
	os.WriteFile(badPath, bad, 0644)
	_, tampered := openVault(badPath, pw, key)
	shortPath := filepath.Join(tmp, "short.zif")
	os.WriteFile(shortPath, raw[:len(raw)-20], 0644)
	_, truncated := openVault(shortPath, pw, key)

	hdrBad := append([]byte(nil), raw...)
	hdrBad[len(magic)] ^= 1
	hdrBadPath := filepath.Join(tmp, "hdrbad.zif")
	os.WriteFile(hdrBadPath, hdrBad, 0644)
	_, hdrTampered := openVault(hdrBadPath, pw, key)
	hdrBad[len(magic)] = 0xff
	os.WriteFile(hdrBadPath, hdrBad, 0644)
	_, hdrRange := openVault(hdrBadPath, pw, key)

	ok := same && noOverwrite && noSymlink && wrongPw != nil && tampered != nil && truncated != nil &&
		hdrTampered != nil && hdrRange != nil
	return ok, fmt.Sprintf("%d chunks, files identical: %v; refused: wrong password, flipped byte, truncation: %v; "+
		"altered or out-of-range KDF setting in header refused: %v; "+
		"existing file not overwritten: %v; symlink not followed: %v; RAM use: 2 x %d KiB buffers",
		v.chunks, same, wrongPw != nil && tampered != nil && truncated != nil, hdrTampered != nil && hdrRange != nil,
		noOverwrite, noSymlink, chunkSize/1024)
}

func zipSource(source string, w io.Writer) error {
	archive := zip.NewWriter(w)

	base := filepath.Dir(source)

	err := filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			fmt.Fprintf(os.Stderr, "  [!] skipped (not a regular file): %s\n", path)
			return nil
		}
		rel, err := filepath.Rel(base, path)
		if err != nil {
			return err
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(rel)
		if info.IsDir() {
			header.Name += "/"
		} else {
			header.Method = zip.Deflate
		}

		zw, err := archive.CreateHeader(header)
		if err != nil || info.IsDir() {
			return err
		}
		return copyFileTo(zw, path)
	})
	if err != nil {
		archive.Close()
		return err
	}
	return archive.Close()
}

func copyFileTo(w io.Writer, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}

func entryPath(target string, f *zip.File) (string, error) {
	m := f.Mode()
	if !m.IsRegular() && !m.IsDir() {
		return "", fmt.Errorf("unsupported entry type in archive: %s", f.Name)
	}
	path := filepath.Join(target, f.Name)
	if path != target && !strings.HasPrefix(path, target+string(os.PathSeparator)) {
		return "", fmt.Errorf("illegal path in archive: %s", f.Name)
	}
	return path, nil
}

func safeMkdirAll(target, dir string, created *[]string) error {
	rel, err := filepath.Rel(target, dir)
	if err != nil {
		return err
	}
	if rel == "." {
		return os.MkdirAll(target, 0755)
	}
	cur := target
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		cur = filepath.Join(cur, part)
		st, err := os.Lstat(cur)
		switch {
		case err == nil && st.Mode()&os.ModeSymlink != 0:
			return fmt.Errorf("refusing to follow symlink: %s", cur)
		case err == nil && !st.IsDir():
			return fmt.Errorf("exists and is not a folder: %s", cur)
		case err == nil:
		case os.IsNotExist(err):
			if err := os.Mkdir(cur, 0755); err != nil {
				return err
			}
			*created = append(*created, cur)
		default:
			return err
		}
	}
	return nil
}

func unzipReader(ra io.ReaderAt, size int64, targetDir string) (err error) {
	target, err := filepath.Abs(targetDir)
	if err != nil {
		return err
	}
	reader, err := zip.NewReader(ra, size)
	if err != nil {
		return err
	}

	seen := make(map[string]bool, len(reader.File))
	for _, f := range reader.File {
		path, err := entryPath(target, f)
		if err != nil {
			return err
		}
		if f.FileInfo().IsDir() {
			continue
		}
		if seen[path] {
			return fmt.Errorf("duplicate entry in archive: %s", f.Name)
		}
		seen[path] = true
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("refusing to overwrite existing file: %s (use an empty output folder)", path)
		} else if !os.IsNotExist(err) {
			return err
		}
	}

	if err := os.MkdirAll(target, 0755); err != nil {
		return err
	}
	var files, dirs []string
	defer func() {
		if err != nil {
			for _, p := range files {
				os.Remove(p)
			}
			for i := len(dirs) - 1; i >= 0; i-- {
				os.Remove(dirs[i])
			}
		}
	}()

	for _, f := range reader.File {
		path, err := entryPath(target, f)
		if err != nil {
			return err
		}
		if f.FileInfo().IsDir() {
			if err := safeMkdirAll(target, path, &dirs); err != nil {
				return err
			}
			continue
		}
		if err := safeMkdirAll(target, filepath.Dir(path), &dirs); err != nil {
			return err
		}
		if err := extractFile(f, path); err != nil {
			return err
		}
		files = append(files, path)
	}
	return nil
}

func extractFile(f *zip.File, path string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, f.Mode().Perm()|0600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, rc); err != nil {
		out.Close()
		os.Remove(path)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

func randomStem() (string, error) {
	b := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func isInside(child, parent string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

func compressItem(srcPath, destDir, keyTarget string, password []byte) (vaultPath, keyPath string, err error) {
	absSrc, err := filepath.Abs(srcPath)
	if err != nil {
		return "", "", err
	}
	absDest, err := filepath.Abs(destDir)
	if err != nil {
		return "", "", err
	}
	if isInside(absDest, absSrc) {
		return "", "", errors.New("destination must not be inside the source")
	}

	stem, err := randomStem()
	if err != nil {
		return "", "", err
	}
	vPath := filepath.Join(absDest, stem+vaultExt)

	var kPath string
	switch {
	case strings.HasSuffix(strings.ToLower(keyTarget), ".txt"):
		kPath, err = filepath.Abs(keyTarget)
	case keyTarget != "":
		var keyDir string
		keyDir, err = filepath.Abs(keyTarget)
		kPath = filepath.Join(keyDir, stem+keyExt)
	default:
		kPath = filepath.Join(absDest, stem+keyExt)
	}
	if err != nil {
		return "", "", err
	}
	if isInside(kPath, absSrc) {
		return "", "", errors.New("key file must not be inside the source")
	}

	if err := os.MkdirAll(absDest, 0755); err != nil {
		return "", "", err
	}
	if err := os.MkdirAll(filepath.Dir(kPath), 0755); err != nil {
		return "", "", err
	}

	var created []string
	var f *os.File
	defer func() {
		if err != nil {
			if f != nil {
				f.Close()
			}
			for _, p := range created {
				os.Remove(p)
			}
		}
	}()

	key, err := generateKey()
	if err != nil {
		return "", "", err
	}

	kf, err := os.OpenFile(kPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", "", err
	}
	created = append(created, kPath)
	if _, err = kf.WriteString(key.text()); err != nil {
		kf.Close()
		return "", "", err
	}
	if err = kf.Close(); err != nil {
		return "", "", err
	}

	if _, statErr := os.Lstat(vPath); statErr == nil {
		return "", "", fmt.Errorf("refusing to overwrite existing file: %s", vPath)
	}
	tmpPath := vPath + ".tmp"
	f, err = os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return "", "", err
	}
	created = append(created, tmpPath)

	enc, err := newEncWriter(f, password, key)
	if err != nil {
		return "", "", fmt.Errorf("encryption failed: %v", err)
	}
	if err = zipSource(absSrc, enc); err != nil {
		return "", "", fmt.Errorf("compression failed: %v", err)
	}
	if err = enc.Close(); err != nil {
		return "", "", fmt.Errorf("encryption failed: %v", err)
	}
	if err = f.Sync(); err != nil {
		return "", "", err
	}
	if err = f.Close(); err != nil {
		return "", "", err
	}
	if err = os.Rename(tmpPath, vPath); err != nil {
		return "", "", err
	}
	return vPath, kPath, nil
}

func decompressSingleFile(archivePath, destDir string, password []byte, key *keyConfig) error {
	v, err := openVault(archivePath, password, key)
	if err != nil {
		return fmt.Errorf("decryption failed: %v", err)
	}
	defer v.Close()
	if err := unzipReader(v, v.size, destDir); err != nil {
		return fmt.Errorf("extraction failed: %v", err)
	}
	return nil
}

func vaultStem(path string) string {
	return strings.TrimSuffix(filepath.Base(path), vaultExt)
}

func resolveKey(vaultPath, keyArg string) (*keyConfig, error) {
	if keyArg == "" {
		return pasteKey()
	}
	path := keyArg
	if st, err := os.Stat(path); err == nil && st.IsDir() {
		path = filepath.Join(path, vaultStem(vaultPath)+keyExt)
	}
	return loadKeyFile(path)
}

func printHelp() {
	fmt.Println("ZIF - ZIF Is File-vault")
	fmt.Println("Simple CLI File Compression & Enigma Encryption Tool")
	fmt.Println("\nUsage:")
	fmt.Println("  zif -c <file_or_dir> -o <output_dir> [-k <key_dir | key_file.txt>]")
	fmt.Println("      Compress + encrypt -> 1 .zif vault + 1 random Enigma key file (.zifkey.txt)")
	fmt.Println("  zif -d <vault | dir> -o <output_dir> [-k <key_file.txt | key_dir>]")
	fmt.Println("      Decrypt + decompress one vault, or every .zif inside a folder")
	fmt.Println("\nThe password is asked interactively by the tool (hidden while typing).")
	fmt.Println("The key file is random for every vault, even with the same password.")
	fmt.Println("Keep it SEPARATE from the vault: without it (and the password) there is no recovery.")
	fmt.Println("The key is never searched automatically. On -d give it with -k;")
	fmt.Println("for a single vault without -k you can paste the key block into the terminal.")
	fmt.Println("For a folder of vaults, -k <key_folder> is required.")
	fmt.Println("Extraction never overwrites existing files and never follows symlinks:")
	fmt.Println("use an empty (or new) output folder.")
	fmt.Println("\nOptions:")
	fmt.Println("  -c, --compress     Compress + encrypt")
	fmt.Println("  -d, --decompress   Decrypt + decompress")
	fmt.Println("  -o, --output       Output directory")
	fmt.Println("  -k, --key          Key file / key folder (see usage)")
	fmt.Println("  -t, --selftest     Run the built-in cipher sanity tests")
	fmt.Println("  -h, --help         Show help")
	fmt.Println("\nThe file or folder to process is given directly, e.g.: zif -c photo.jpg -o ./vault")
}

func report(path string) {
	if st, err := os.Stat(path); err == nil {
		fmt.Printf("  -> %s (%d bytes)\n", path, st.Size())
	} else {
		fmt.Printf("  -> %s\n", path)
	}
}

func doCompress(src, dest, keyTarget string, password []byte) error {
	fmt.Printf("Compressing '%s' into 1 vault...\n", src)
	vault, key, err := compressItem(src, dest, keyTarget, password)
	if err != nil {
		return err
	}
	fmt.Println("Vault:")
	report(vault)
	fmt.Println("Key file (random Enigma configuration):")
	report(key)
	fmt.Println("\nKeep the key file SEPARATE from the vault. Without it the vault cannot be opened.")
	fmt.Println("Done.")
	return nil
}

func doDecompress(src, dest, keyArg string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}

	if !info.IsDir() {
		key, err := resolveKey(src, keyArg)
		if err != nil {
			return err
		}
		password, err := askPassword(false)
		if err != nil {
			return err
		}
		defer wipe(password)
		fmt.Printf("Decompressing file '%s'...\n", src)
		if err := decompressSingleFile(src, dest, password, key); err != nil {
			return err
		}
		fmt.Println("\nDecryption & Decompression Completed Successfully!")
		return nil
	}

	if keyArg == "" {
		return errors.New("when decompressing a folder, -k <key_folder> is required")
	}
	st, err := os.Stat(keyArg)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return errors.New("when decompressing a folder, -k must be a folder with the key files")
	}
	keyDir := keyArg

	password, err := askPassword(false)
	if err != nil {
		return err
	}
	defer wipe(password)
	fmt.Printf("Decompressing all archives inside folder '%s'...\n", src)
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	ok, failed := 0, 0
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, vaultExt) {
			continue
		}
		key, err := loadKeyFile(filepath.Join(keyDir, vaultStem(n)+keyExt))
		if err == nil {
			err = decompressSingleFile(filepath.Join(src, n), dest, password, key)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "  [!] Failed %s: %v\n", n, err)
			failed++
			continue
		}
		fmt.Printf("  OK %s\n", n)
		ok++
	}
	fmt.Printf("\nDecompression finished: %d unpacked, %d failed.\n", ok, failed)
	if failed > 0 {
		return fmt.Errorf("%d archive(s) failed", failed)
	}
	return nil
}

var stdin = bufio.NewReader(os.Stdin)

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func disableEcho() (restore func(), err error) {
	run := func(arg string) error {
		cmd := exec.Command("stty", arg)
		cmd.Stdin = os.Stdin
		return cmd.Run()
	}
	if err := run("-echo"); err != nil {
		return nil, err
	}
	return func() { run("echo") }, nil
}

func readPasswordWindows() ([]byte, error) {
	script := `$p = Read-Host -AsSecureString; ` +
		`$b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p); ` +
		`try { $s = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) } ` +
		`finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }; ` +
		`[Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)))`
	var out bytes.Buffer
	cmd := exec.Command("powershell", "-NoProfile", "-Command", script)
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		wipe(out.Bytes())
		return nil, err
	}
	enc := bytes.TrimSpace(out.Bytes())
	raw := make([]byte, base64.StdEncoding.DecodedLen(len(enc)))
	n, err := base64.StdEncoding.Decode(raw, enc)
	wipe(out.Bytes())
	if err != nil {
		wipe(raw)
		return nil, err
	}
	pw := make([]byte, n)
	copy(pw, raw[:n])
	wipe(raw)
	return pw, nil
}

func appendSecret(dst, src []byte) []byte {
	if len(dst)+len(src) > cap(dst) {
		nd := make([]byte, len(dst), 2*(len(dst)+len(src))+64)
		copy(nd, dst)
		wipe(dst[:cap(dst)])
		dst = nd
	}
	return append(dst, src...)
}

func readSecretLine(r *bufio.Reader) ([]byte, error) {
	var out []byte
	for {
		frag, err := r.ReadSlice('\n')
		out = appendSecret(out, frag)
		wipe(frag)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil && (err != io.EOF || len(out) == 0) {
			wipe(out)
			return nil, err
		}
		break
	}
	for len(out) > 0 && (out[len(out)-1] == '\n' || out[len(out)-1] == '\r') {
		out[len(out)-1] = 0
		out = out[:len(out)-1]
	}
	return out, nil
}

func readPassword(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	interactive := isTerminal(os.Stdin)

	if interactive && runtime.GOOS == "windows" {
		if pw, err := readPasswordWindows(); err == nil {
			fmt.Fprintln(os.Stderr)
			return pw, nil
		}

		fmt.Fprint(os.Stderr, "(warning: input will be visible) ")
	}

	var restore func()
	if interactive && runtime.GOOS != "windows" {
		r, err := disableEcho()
		if err != nil {
			fmt.Fprint(os.Stderr, "(warning: input will be visible) ")
		} else {
			restore = r
		}
	}

	if restore != nil {
		sig := make(chan os.Signal, 1)
		done := make(chan struct{})
		signal.Notify(sig, os.Interrupt)
		go func() {
			select {
			case <-sig:
				restore()
				fmt.Fprintln(os.Stderr)
				os.Exit(130)
			case <-done:
			}
		}()
		defer close(done)
		defer signal.Stop(sig)
		defer restore()
	}

	pw, err := readSecretLine(stdin)
	if interactive {
		fmt.Fprintln(os.Stderr)
	}
	if err != nil {
		return nil, errors.New("could not read password")
	}
	return pw, nil
}

func askPassword(confirm bool) ([]byte, error) {
	pw, err := readPassword("Password: ")
	if err != nil {
		return nil, err
	}
	if len(pw) == 0 {
		return nil, errors.New("password must not be empty")
	}
	if confirm {
		pw2, err := readPassword("Confirm password: ")
		if err != nil {
			wipe(pw)
			return nil, err
		}
		same := subtle.ConstantTimeCompare(pw, pw2) == 1
		wipe(pw2)
		if !same {
			wipe(pw)
			return nil, errors.New("passwords do not match")
		}
	}
	return pw, nil
}

func reorderArgs(args []string) []string {
	var flags, rest []string
	sawDash := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			sawDash = true
			rest = append(rest, args[i+1:]...)
			break
		}
		if len(a) > 1 && strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			switch name {
			case "o", "out", "output", "k", "key":
				if i+1 < len(args) {
					i++
					flags = append(flags, args[i])
				}
			}
			continue
		}
		rest = append(rest, a)
	}
	if sawDash {
		flags = append(flags, "--")
	}
	return append(flags, rest...)
}

func run() error {
	var out, keyArg string
	var compress, decompress, selftest bool

	flag.BoolVar(&compress, "c", false, "")
	flag.BoolVar(&compress, "compress", false, "")
	flag.BoolVar(&decompress, "d", false, "")
	flag.BoolVar(&decompress, "decompress", false, "")
	flag.StringVar(&out, "o", "", "")
	flag.StringVar(&out, "out", "", "")
	flag.StringVar(&out, "output", "", "")
	flag.StringVar(&keyArg, "k", "", "")
	flag.StringVar(&keyArg, "key", "", "")
	flag.BoolVar(&selftest, "t", false, "")
	flag.BoolVar(&selftest, "selftest", false, "")
	flag.Usage = printHelp
	flag.CommandLine.Parse(reorderArgs(os.Args[1:]))

	if selftest {
		return selfTest()
	}

	if compress == decompress {
		printHelp()
		return errors.New("choose exactly one action: -c (compress) or -d (decompress)")
	}
	if flag.NArg() != 1 {
		printHelp()
		return errors.New("give exactly one file or folder, e.g. zif -c FILE -o OUTPUT_DIR")
	}
	src := flag.Arg(0)
	if out == "" {
		printHelp()
		return errors.New("missing required option -o (output directory)")
	}

	if _, err := os.Stat(src); err != nil {
		return err
	}

	if compress {
		password, err := askPassword(true)
		if err != nil {
			return err
		}
		defer wipe(password)
		return doCompress(src, out, keyArg, password)
	}
	return doDecompress(src, out, keyArg)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}