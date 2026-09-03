// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package ratls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"sync"
	"time"
)

// Leaf keys are package state, not module state: Caddy re-provisions modules
// on every config load, and a deploy that only changes extension values must
// re-mint the certificate with the SAME key so a deterministic quote minted
// for that key stays valid. A key lives leafLifetime; the previous key of a
// name is kept for previousRetention so a client that received the old leaf
// just before a rotation can still be answered.

// previousRetention is how long a rotated key stays answerable.
const previousRetention = 15 * time.Minute

// leafKey is the key of one SNI, with the deterministic quote minted for it.
type leafKey struct {
	sni      string
	key      *ecdsa.PrivateKey
	spkiDER  []byte
	spkiHash [32]byte
	created  time.Time

	mu  sync.Mutex
	det *cachedQuote
}

// cachedQuote is the deterministic quote of a key: report_data commits to the
// key, the minute it was minted, and the GPU evidence current at that time.
type cachedQuote struct {
	quote     []byte
	quoteTime string
	gpu       []byte
	gpuSum    [32]byte
	minted    time.Time
}

var leaves = struct {
	mu     sync.Mutex
	bySNI  map[string]*leafKey
	bySPKI map[[32]byte]*leafKey
}{bySNI: map[string]*leafKey{}, bySPKI: map[[32]byte]*leafKey{}}

// leafKeyFor returns the current key of an SNI, rotating it when it is older
// than leafLifetime and purging keys past their retention.
func leafKeyFor(sni string) *leafKey {
	leaves.mu.Lock()
	defer leaves.mu.Unlock()
	now := time.Now()
	for h, lk := range leaves.bySPKI {
		if now.Sub(lk.created) > leafLifetime+previousRetention {
			delete(leaves.bySPKI, h)
		}
	}
	if lk, ok := leaves.bySNI[sni]; ok && now.Sub(lk.created) < leafLifetime {
		return lk
	}
	lk, err := newLeafKey(sni, now)
	if err != nil {
		// Key generation failing is a broken system RNG; the handshake fails
		// closed at the caller because the certificate cannot be minted.
		panic(fmt.Sprintf("ra_tls: leaf key generation failed: %v", err))
	}
	leaves.bySNI[sni] = lk
	leaves.bySPKI[lk.spkiHash] = lk
	return lk
}

// leafBySPKI returns the key whose SHA-256(SPKI) is h, current or recently
// rotated, or nil.
func leafBySPKI(h [32]byte) *leafKey {
	leaves.mu.Lock()
	defer leaves.mu.Unlock()
	return leaves.bySPKI[h]
}

func newLeafKey(sni string, now time.Time) (*leafKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &leafKey{
		sni:      sni,
		key:      key,
		spkiDER:  spki,
		spkiHash: sha256.Sum256(spki),
		created:  now,
	}, nil
}

// reportData is SHA-512( SHA-256(SPKI_DER) || binding ), the report_data of
// every RA-TLS v2 recipe.
func reportData(spkiHash [32]byte, binding []byte) [64]byte {
	input := make([]byte, 0, 32+len(binding))
	input = append(input, spkiHash[:]...)
	input = append(input, binding...)
	return sha512.Sum512(input)
}

// deterministicQuote returns the cached deterministic quote of lk, minting it
// when there is none, when it is older than leafLifetime, or when the GPU
// evidence it commits to has changed.
func (lk *leafKey) deterministicQuote(g *RATLSCertGetter) (*cachedQuote, error) {
	gpu, gpuSum, gpuOK := loadGPUEvidence(g.GPUEvidenceDir)
	lk.mu.Lock()
	defer lk.mu.Unlock()
	if lk.det != nil && time.Since(lk.det.minted) < leafLifetime && (!gpuOK || lk.det.gpuSum == gpuSum) && (gpuOK || lk.det.gpu == nil) {
		return lk.det, nil
	}
	now := time.Now().UTC().Truncate(time.Minute)
	quoteTime := now.Format(quoteTimeLayout)
	binding := gpuBinding([]byte(quoteTime), gpuSum, gpuOK)
	rd := reportData(lk.spkiHash, binding)
	quote, err := g.attester.Quote(rd)
	if err != nil {
		return nil, err
	}
	lk.det = &cachedQuote{quote: quote, quoteTime: quoteTime, minted: now}
	if gpuOK {
		lk.det.gpu, lk.det.gpuSum = gpu, gpuSum
	}
	return lk.det, nil
}
