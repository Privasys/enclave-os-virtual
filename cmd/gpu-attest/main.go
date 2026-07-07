// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// gpu-attest collects NVIDIA GPU Confidential-Computing attestation evidence
// bound to a nonce and writes it where the RA-TLS cert issuer reads it:
//
//	<out>/gpu-evidence.bin      the marshaled evidence envelope
//	<out>/gpu-evidence.sha256   hex SHA-256 of the envelope (folded into REPORTDATA)
//
// Modes:
//   - deterministic (default): the report nonce is bound to the UTC day, so
//     the evidence is regenerated at most once per day. --daemon keeps it
//     current on a timer; the RA-TLS deterministic cert path reads the cache.
//   - challenge: the report nonce is derived from --client-nonce (the
//     ClientHello challenge); one-shot, used by the interactive attest path.
//
// See gpu-attestation-plan.md (D1, the two attestation modes).
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Privasys/enclave-os-virtual/internal/gpuattest"
)

func main() {
	mode := flag.String("mode", "deterministic", "deterministic | challenge")
	clientNonceHex := flag.String("client-nonce", "", "challenge mode: RA-TLS ClientHello nonce (hex)")
	rawNonceHex := flag.String("nonce", "", "override: use this raw 32-byte nonce (hex, testing)")
	outDir := flag.String("out", "/run", "directory for gpu-evidence.bin / .sha256")
	daemon := flag.Bool("daemon", false, "deterministic mode: refresh on a timer")
	refresh := flag.Duration("refresh", 6*time.Hour, "daemon: max re-collect interval within a day window")
	poll := flag.Duration("poll", time.Minute, "daemon: window-change poll interval")
	write := flag.Bool("write", true, "write the evidence files")
	printSummary := flag.Bool("print", true, "print a human summary to stderr")
	flag.Parse()

	nonceFor := func(now time.Time) ([gpuattest.NonceSize]byte, error) {
		var n [gpuattest.NonceSize]byte
		switch {
		case *rawNonceHex != "":
			b, err := hex.DecodeString(*rawNonceHex)
			if err != nil || len(b) != gpuattest.NonceSize {
				return n, fmt.Errorf("--nonce must be %d hex bytes", gpuattest.NonceSize)
			}
			copy(n[:], b)
		case *mode == "challenge":
			if *clientNonceHex == "" {
				return n, fmt.Errorf("challenge mode requires --client-nonce")
			}
			cb, err := hex.DecodeString(*clientNonceHex)
			if err != nil {
				return n, fmt.Errorf("--client-nonce must be hex")
			}
			n = gpuattest.ChallengeNonce(cb)
		case *mode == "deterministic":
			n = gpuattest.DeterministicNonce(now)
		default:
			return n, fmt.Errorf("unknown --mode %q", *mode)
		}
		return n, nil
	}

	if *daemon {
		if *mode != "deterministic" {
			fmt.Fprintln(os.Stderr, "gpu-attest: --daemon requires deterministic mode")
			os.Exit(2)
		}
		runDaemon(nonceFor, *outDir, *refresh, *poll, *printSummary)
		return
	}

	nonce, err := nonceFor(time.Now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "gpu-attest: %v\n", err)
		os.Exit(2)
	}
	if err := once(nonce, *outDir, *write, *printSummary); err != nil {
		if err == gpuattest.ErrUnavailable || errIsUnavailable(err) {
			fmt.Fprintf(os.Stderr, "gpu-attest: %v\n", err)
			os.Exit(3) // "no GPU" — caller skips GPU evidence
		}
		fmt.Fprintf(os.Stderr, "gpu-attest: %v\n", err)
		os.Exit(1)
	}
}

// runDaemon regenerates the deterministic evidence when the UTC day window
// rolls over or the refresh interval elapses, and on a missing cache file.
func runDaemon(nonceFor func(time.Time) ([gpuattest.NonceSize]byte, error), outDir string, refresh, poll time.Duration, printSummary bool) {
	binPath := filepath.Join(outDir, "gpu-evidence.bin")
	var lastNonce [gpuattest.NonceSize]byte
	var lastAt time.Time
	for {
		now := time.Now()
		nonce, err := nonceFor(now)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gpu-attest daemon: %v\n", err)
			os.Exit(2)
		}
		_, statErr := os.Stat(binPath)
		need := nonce != lastNonce || os.IsNotExist(statErr) || now.Sub(lastAt) >= refresh
		if need {
			if err := once(nonce, outDir, true, printSummary); err != nil {
				// Non-fatal: log and retry next poll (transient NVML hiccup, or
				// a host that lost its GPU — the issuer just omits evidence).
				fmt.Fprintf(os.Stderr, "gpu-attest daemon: collect failed: %v\n", err)
			} else {
				lastNonce = nonce
				lastAt = now
			}
		}
		time.Sleep(poll)
	}
}

func once(nonce [gpuattest.NonceSize]byte, outDir string, write, printSummary bool) error {
	ev, err := gpuattest.Collect(nonce)
	if err != nil {
		return err
	}
	envelope := ev.Marshal()
	sum := ev.Sha256()
	sumHex := hex.EncodeToString(sum[:])
	if write {
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return err
		}
		if err := writeAtomic(filepath.Join(outDir, "gpu-evidence.bin"), envelope, 0o644); err != nil {
			return err
		}
		if err := writeAtomic(filepath.Join(outDir, "gpu-evidence.sha256"), []byte(sumHex+"\n"), 0o644); err != nil {
			return err
		}
	}
	if printSummary {
		fmt.Fprintf(os.Stderr,
			"gpu-attest OK gpu=%s driver=%s vbios=%s cc_env=%d cc_feature=%d devtools=%d "+
				"report=%dB chain=%dB cec=%dB envelope=%dB nonce=%s sha256=%s\n",
			ev.GPUUUID, ev.DriverVersion, ev.VBIOSVersion, ev.CCEnvironment, ev.CCFeature, ev.DevToolsMode,
			len(ev.AttestationReport), len(ev.AttestationCertChain), len(ev.CecReport),
			len(envelope), hex.EncodeToString(ev.Nonce[:]), sumHex)
	}
	return nil
}

func errIsUnavailable(err error) bool {
	for e := err; e != nil; {
		if e == gpuattest.ErrUnavailable {
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}

// writeAtomic writes via a temp file + rename so a reader never sees a partial.
func writeAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".gpu-evidence-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
