package honeypot

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"testing"
)

func want(t *testing.T, got, expected error) {
	t.Helper()
	if !errors.Is(got, expected) {
		t.Fatalf("got %v, want %v", got, expected)
	}
}

func TestNewIssuer(t *testing.T) {
	_, err := NewIssuer(1, make([]byte, 31))
	want(t, err, ErrKeySize)
	a, b := mustIssuer(t, 1, mainTag), mustIssuer(t, 1, mainTag)
	if !bytes.Equal(a.Public(), b.Public()) || !bytes.Equal(a.root, b.root) {
		t.Fatal("a main key must always split the same way")
	}
	if bytes.Equal(a.root, a.sign.Bytes()) {
		t.Fatal("the signing key and the root must be independent")
	}
	if len(a.Public()) != PublicKeySize {
		t.Fatal(len(a.Public()))
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	is := mustIssuer(t, 1, mainTag)
	keys := is.keys()
	for _, payload := range [][]byte{{}, []byte("sword"), bytes.Repeat([]byte{7}, chest.Size-2)} {
		b, err := is.Seal(rand.Reader, chest, payload)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeBox(b.Encode())
		if err != nil {
			t.Fatal(err)
		}
		if err := got.Verify(keys); err != nil {
			t.Fatal(err)
		}
		// The key comes from the decoded box, as it would on a key server.
		key := is.Key(got)
		if err := got.VerifyKey(key); err != nil {
			t.Fatal(err)
		}
		plain, err := got.Open(keys, key)
		if err != nil || !bytes.Equal(plain, payload) {
			t.Fatalf("%q %v", plain, err)
		}
		if got.Series != chest.Series || !bytes.Equal(got.Meta, chest.Meta) {
			t.Fatal("public fields lost")
		}
	}
}

func TestSealRejects(t *testing.T) {
	is := mustIssuer(t, 1, mainTag)
	_, err := is.Seal(rand.Reader, Spec{Series: strings.Repeat("x", 256), Size: 8}, nil)
	want(t, err, ErrTooLong)
	_, err = is.Seal(rand.Reader, Spec{Meta: make([]byte, 65536), Size: 8}, nil)
	want(t, err, ErrTooLong)
	_, err = is.Seal(rand.Reader, Spec{Size: 6}, []byte("sword"))
	want(t, err, ErrSize)
	_, err = is.Seal(rand.Reader, Spec{Size: MaxSize + 1}, nil)
	want(t, err, ErrSize)
	_, err = is.Seal(failReader{}, Spec{Size: 8}, nil)
	want(t, err, errRNG)
	if _, err = is.Seal(rand.Reader, Spec{Size: MaxSize}, nil); err != nil {
		t.Fatal(err)
	}
}

// The size of a box must not say what it holds.
func TestAllBoxesOfASeriesAreTheSameSize(t *testing.T) {
	is := mustIssuer(t, 1, mainTag)
	common, _ := is.Seal(rand.Reader, chest, []byte("x"))
	legendary, _ := is.Seal(rand.Reader, chest, bytes.Repeat([]byte("L"), chest.Size-2))
	if len(common.Encode()) != len(legendary.Encode()) {
		t.Fatal("a box leaks the length of its payload")
	}
}

// Nothing public may let a guess be tested: no field is a function of the
// payload that can be computed without a secret.
func TestContentsAreNotCheckable(t *testing.T) {
	is := mustIssuer(t, 1, mainTag)
	payload := []byte("legendary sword")
	raw := sealAt(t, is, "a", chest, payload).Encode()
	sum := sha256.Sum256(payload)
	if bytes.Contains(raw, payload) || bytes.Contains(raw, sum[:]) {
		t.Fatal("payload visible in the box")
	}
	// Same payload, different box: two boxes cannot be compared either.
	a, b := sealAt(t, is, "a", chest, payload), sealAt(t, is, "b", chest, payload)
	if a.Nonce == b.Nonce || a.KeyCommit == b.KeyCommit || bytes.Equal(a.Ciphertext, b.Ciphertext) {
		t.Fatal("equal payloads are visible across boxes")
	}
}

func TestBrokenRNGNeverReusesAKey(t *testing.T) {
	is := mustIssuer(t, 1, mainTag)
	a, b := sealAt(t, is, "stuck", chest, []byte("sword")), sealAt(t, is, "stuck", chest, []byte("shield"))
	if a.ID() == b.ID() || bytes.Equal(is.Key(a), is.Key(b)) {
		t.Fatal("two plaintexts under one open key")
	}
	again := sealAt(t, is, "stuck", chest, []byte("sword"))
	if !bytes.Equal(a.Encode(), again.Encode()) {
		t.Fatal("the same input must give the same box")
	}
}

func TestAKeyOpensOneBox(t *testing.T) {
	is := mustIssuer(t, 1, mainTag)
	keys := is.keys()
	a, b := sealAt(t, is, "a", chest, []byte("sword")), sealAt(t, is, "b", chest, []byte("sword"))
	want(t, b.VerifyKey(is.Key(a)), ErrWrongKey)
	_, err := b.Open(keys, is.Key(a))
	want(t, err, ErrWrongKey)
	_, err = a.Open(keys, is.Key(a)[:31])
	want(t, err, ErrKeySize)
	// A key of the other issuer, or one for an altered header, is a different key.
	other := mustIssuer(t, 1, otherTag)
	want(t, a.VerifyKey(other.Key(a)), ErrWrongKey)
	moved := a
	moved.Series = "acme/season-1/bronze"
	want(t, a.VerifyKey(is.Key(moved)), ErrWrongKey)
}

func TestVerify(t *testing.T) {
	is, other := mustIssuer(t, 1, mainTag), mustIssuer(t, 1, otherTag)
	keys := is.keys()
	b := sealAt(t, is, "a", assigned("alice"), []byte("sword"))
	if err := b.Verify(keys); err != nil {
		t.Fatal(err)
	}
	want(t, b.Verify(map[uint8][]byte{2: is.Public()}), ErrUnknownKey)
	want(t, b.Verify(map[uint8][]byte{1: other.Public()}), ErrSignature)
	want(t, b.Verify(map[uint8][]byte{1: make([]byte, 31)}), ErrSignature)
	short := b
	short.Sig = b.Sig[:SigSize-1]
	want(t, short.Verify(keys), ErrSignature)
	// Every single byte of a box is covered: flip each one.
	raw := b.Encode()
	for i := range raw {
		bad := bytes.Clone(raw)
		bad[i] ^= 0x01
		got, err := DecodeBox(bad)
		if err == nil && got.Verify(keys) == nil {
			t.Fatalf("flipped byte %d still verifies", i)
		}
	}
	_, err := b.Open(map[uint8][]byte{}, is.Key(b))
	want(t, err, ErrUnknownKey)
}

func TestDecodeRejects(t *testing.T) {
	raw := sealAt(t, mustIssuer(t, 1, mainTag), "a", assigned("alice"), []byte("sword")).Encode()
	_, err := DecodeBox(nil)
	want(t, err, ErrShort)
	_, err = DecodeBox(append([]byte("HPBOX999"), raw[8:]...))
	want(t, err, ErrTag)
	_, err = DecodeBox(append(bytes.Clone(raw), 0))
	want(t, err, ErrTrailing)
	for n := range raw {
		if _, err := DecodeBox(raw[:n]); err == nil {
			t.Fatalf("truncated to %d bytes and decoded", n)
		}
	}
}

// An issuer can sign anything; a box whose ciphertext or padding is broken is
// rejected, and the same plaintext has one byte form.
func TestOpenRejectsADishonestIssuer(t *testing.T) {
	is := mustIssuer(t, 1, mainTag)
	keys := is.keys()
	spec := Spec{Series: "x", Size: 8}

	b := sealAt(t, is, "a", spec, []byte("sword"))
	key := is.Key(b)
	b.Ciphertext = bytes.Clone(b.Ciphertext)
	b.Ciphertext[0] ^= 1
	b.Sig = is.signBox(b)
	_, err := b.Open(keys, key)
	want(t, err, ErrCiphertext)

	for name, plain := range map[string][]byte{
		"too short":        {0},
		"length past end":  {0, 9, 1, 2},
		"bytes in padding": {0, 1, 'x', 0, 1},
	} {
		bad := is.seal(entropyOf(name), spec, plain)
		_, err := bad.Open(keys, is.Key(bad))
		if !errors.Is(err, ErrPadding) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// Properties can be read from the box by anyone with no key at all, and cannot
// be changed without the main key.
func TestProperties(t *testing.T) {
	is := mustIssuer(t, 1, mainTag)
	spec := chest
	spec.Props = map[string]string{PropUser: "alice", "level": "3", "é": "✓", "empty": ""}
	b := sealAt(t, is, "a", spec, []byte("sword"))
	raw := b.Encode()

	got, err := DecodeBox(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Verify(is.keys()); err != nil {
		t.Fatal(err)
	}
	if len(got.Props) != 4 || got.Props[PropUser] != "alice" || got.Props["é"] != "✓" {
		t.Fatalf("%v", got.Props)
	}
	if !bytes.Equal(got.Encode(), raw) {
		t.Fatal("properties have more than one byte form")
	}
	if !bytes.Contains(raw, []byte("alice")) {
		t.Fatal("a property must be readable on the box")
	}

	forged := got
	forged.Props = map[string]string{PropUser: "mallory", "level": "3", "é": "✓", "empty": ""}
	want(t, forged.Verify(is.keys()), ErrSignature)
	bumped := got
	bumped.Revision = 7
	want(t, bumped.Verify(is.keys()), ErrSignature)
	stripped := got
	stripped.Props = nil
	want(t, stripped.Verify(is.keys()), ErrSignature)
}

func TestPropertiesRejected(t *testing.T) {
	is := mustIssuer(t, 1, mainTag)
	many := map[string]string{}
	for i := range 256 {
		many[string(rune(0x100+i))] = ""
	}
	for name, props := range map[string]map[string]string{
		"too many":     many,
		"empty name":   {"": "x"},
		"long name":    {strings.Repeat("n", 256): "x"},
		"long value":   {"n": strings.Repeat("v", 65536)},
		"binary name":  {"\xff": "x"},
		"binary value": {"n": "\xff"},
	} {
		spec := chest
		spec.Props = props
		_, err := is.Seal(rand.Reader, spec, nil)
		if !errors.Is(err, ErrProperty) {
			t.Fatalf("seal, %s: %v", name, err)
		}
		l := newLedger()
		b := sealAt(t, is, "a", chest, nil)
		_, err = is.Rewrite(l, b, props)
		if !errors.Is(err, ErrProperty) {
			t.Fatalf("rewrite, %s: %v", name, err)
		}
		if len(l.rows) != 0 {
			t.Fatalf("rewrite, %s: a refused rewrite took a revision", name)
		}
	}
}

func TestDecodeRejectsProperties(t *testing.T) {
	b := sealAt(t, mustIssuer(t, 1, mainTag), "a", chest, nil)
	for name, props := range map[string][]byte{
		"out of order": {2, 1, 'b', 0, 0, 1, 'a', 0, 0},
		"duplicate":    {2, 1, 'a', 0, 0, 1, 'a', 0, 0},
		"empty name":   {1, 0, 0, 0},
		"binary name":  {1, 1, 0xff, 0, 0},
		"binary value": {1, 1, 'a', 0, 1, 0xff},
	} {
		raw := append(appendU32(b.sealed(), 0), props...)
		_, err := DecodeBox(append(raw, b.Sig...))
		if !errors.Is(err, ErrProperty) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestRewrite(t *testing.T) {
	is, other := mustIssuer(t, 1, mainTag), mustIssuer(t, 1, otherTag)
	keys := is.keys()
	l := newLedger()
	old := sealAt(t, is, "a", assigned("alice"), []byte("sword"))
	key := is.Key(old)
	oldRaw := old.Encode()

	moved, err := is.Rewrite(l, old, map[string]string{PropUser: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeBox(moved.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Verify(keys); err != nil {
		t.Fatal(err)
	}
	if got.Revision != 1 || got.Props[PropUser] != "bob" {
		t.Fatalf("%d %v", got.Revision, got.Props)
	}
	if !bytes.Equal(old.Encode(), oldRaw) {
		t.Fatal("a rewrite must not touch the box it started from")
	}

	// The contents and the key are untouched.
	if got.ID() != old.ID() || !bytes.Equal(is.Key(got), key) {
		t.Fatal("a rewrite changed the box")
	}
	if payload, err := got.Open(keys, key); err != nil || string(payload) != "sword" {
		t.Fatalf("%q %v", payload, err)
	}
	if !got.Supersedes(old) || old.Supersedes(got) || got.Supersedes(got) {
		t.Fatal("revision order")
	}
	if got.Supersedes(sealAt(t, is, "b", chest, []byte("sword"))) {
		t.Fatal("a box superseded another box")
	}
	// A rewrite cannot swap the contents and keep the id.
	swapped := got
	swapped.Ciphertext = bytes.Clone(got.Ciphertext)
	swapped.Ciphertext[0] ^= 1
	if swapped.Supersedes(old) || swapped.ID() == old.ID() {
		t.Fatal("the id must cover the contents")
	}

	// The old revision still verifies: a signature cannot expire. Freshness is
	// the ledger's job, see TestReleaseTransfer.
	if err := old.Verify(keys); err != nil {
		t.Fatal(err)
	}

	// Rewriting from an old base, as after a lost response, takes the next
	// revision and never hands one out twice.
	again, err := is.Rewrite(l, old, map[string]string{PropUser: "carol"})
	if err != nil || again.Revision != 2 {
		t.Fatalf("%d %v", again.Revision, err)
	}
	// A base from above the ledger, as after restoring a backup, still moves up.
	ahead := again
	ahead.Revision = 9
	ahead.Sig = is.signBox(ahead)
	next, err := is.Rewrite(l, ahead, nil)
	if err != nil || next.Revision != 10 {
		t.Fatalf("%d %v", next.Revision, err)
	}

	// Only the main key can rewrite.
	_, err = other.Rewrite(l, old, nil)
	want(t, err, ErrSignature)
	_, err = mustIssuer(t, 2, mainTag).Rewrite(l, old, nil)
	want(t, err, ErrUnknownKey)
	l.err = errors.New("db down")
	_, err = is.Rewrite(l, old, nil)
	want(t, err, l.err)
}

func TestRewriteRaceHandsOutEachRevisionOnce(t *testing.T) {
	is := mustIssuer(t, 1, mainTag)
	l := newLedger()
	b := sealAt(t, is, "a", chest, []byte("sword"))
	var wg sync.WaitGroup
	var seen sync.Map
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := is.Rewrite(l, b, nil)
			if err != nil {
				t.Error(err)
				return
			}
			if _, dup := seen.LoadOrStore(r.Revision, true); dup {
				t.Errorf("revision %d handed out twice", r.Revision)
			}
		}()
	}
	wg.Wait()
}

func TestRelease(t *testing.T) {
	is := mustIssuer(t, 1, mainTag)
	keys := is.keys()
	l := newLedger()
	b := sealAt(t, is, "a", chest, []byte("sword"))

	key, err := is.Release(l, b, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if payload, err := b.Open(keys, key); err != nil || string(payload) != "sword" {
		t.Fatalf("%q %v", payload, err)
	}
	// A retry gets the same key, and nothing was stored but the claim.
	again, err := is.Release(l, b, "alice")
	if err != nil || !bytes.Equal(again, key) {
		t.Fatalf("%x %v", again, err)
	}
	_, err = is.Release(l, b, "bob")
	want(t, err, ErrClaimed)

	// Another signature on the same box is the same row in the ledger.
	twin := b
	twin.Sig = make([]byte, SigSize)
	if twin.ID() != b.ID() {
		t.Fatal("the id must not depend on the signature")
	}

	// Only verified boxes reach the ledger.
	forged := sealAt(t, mustIssuer(t, 1, otherTag), "a", chest, []byte("sword"))
	_, err = is.Release(l, forged, "bob")
	want(t, err, ErrSignature)
	if _, ok := l.rows[forged.ID()]; ok {
		t.Fatal("a forged box took a row")
	}
	_, err = is.Release(l, sealAt(t, mustIssuer(t, 2, mainTag), "a", chest, nil), "bob")
	want(t, err, ErrUnknownKey)

	l.err = errors.New("db down")
	_, err = is.Release(l, sealAt(t, is, "b", chest, nil), "bob")
	want(t, err, l.err)
}

// A box assigned to a user goes to that user, and a transfer really moves it:
// the previous owner's signed copy no longer works.
func TestReleaseTransfer(t *testing.T) {
	is := mustIssuer(t, 1, mainTag)
	keys := is.keys()
	l := newLedger()
	old := sealAt(t, is, "a", assigned("alice"), []byte("sword"))

	_, err := is.Release(l, old, "bob")
	want(t, err, ErrNotOwner)
	if len(l.rows) != 0 {
		t.Fatal("a refused claim took a row")
	}

	moved, err := is.Rewrite(l, old, map[string]string{PropUser: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = is.Release(l, old, "alice")
	want(t, err, ErrStale)
	_, err = is.Release(l, moved, "alice")
	want(t, err, ErrNotOwner)

	key, err := is.Release(l, moved, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if payload, err := moved.Open(keys, key); err != nil || string(payload) != "sword" {
		t.Fatalf("%q %v", payload, err)
	}

	// The claim is final: a later rewrite does not open the box a second time.
	back, err := is.Rewrite(l, moved, map[string]string{PropUser: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = is.Release(l, back, "alice")
	want(t, err, ErrClaimed)
	_, err = is.Release(l, moved, "bob")
	want(t, err, ErrStale)
}

func TestReleaseRaceHasOneWinner(t *testing.T) {
	is := mustIssuer(t, 1, mainTag)
	l := newLedger()
	b := sealAt(t, is, "a", chest, []byte("sword"))
	var wg sync.WaitGroup
	var won sync.Map
	for _, owner := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		wg.Add(1)
		go func(owner string) {
			defer wg.Done()
			if _, err := is.Release(l, b, owner); err == nil {
				won.Store(owner, true)
			}
		}(owner)
	}
	wg.Wait()
	n := 0
	won.Range(func(_, _ any) bool { n++; return true })
	if n != 1 {
		t.Fatalf("%d owners got the key", n)
	}
}
