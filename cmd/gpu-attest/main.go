// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

// gpu-attest collects NVIDIA GPU Confidential-Computing attestation evidence
// bound to a nonce and writes it where the RA-TLS cert issuer reads it:
//
//	<out>/gpu-evidence.bin      the marshaled evidence envelope
//	<out>/gpu-evidence.sha256   hex SHA-256 of the envelope (folded into REPORTDATA)
//
// One-shot by default (used by the deterministic timer that regenerates the
// cached evidence per throttle window). See gpu-attestation-plan.md.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Privasys/enclave-os-virtual/internal/gpuattest"
)

func main() {
	nonceHex := flag.String("nonce", "", "32-byte nonce as 64 hex chars; empty = all-zero (test)")
	outDir := flag.String("out", "/run", "directory for gpu-evidence.bin / .sha256")
	write := flag.Bool("write", true, "write the evidence files")
	printSummary := flag.Bool("print", true, "print a human summary to stderr")
	flag.Parse()

	var nonce [gpuattest.NonceSize]byte
	if *nonceHex != "" {
		b, err := hex.DecodeString(*nonceHex)
		if err != nil || len(b) != gpuattest.NonceSize {
			fmt.Fprintf(os.Stderr, "gpu-attest: --nonce must be %d hex bytes\n", gpuattest.NonceSize)
			os.Exit(2)
		}
		copy(nonce[:], b)
	}

	ev, err := gpuattest.Collect(nonce)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gpu-attest: collect: %v\n", err)
		// ErrUnavailable is exit 3 so a non-GPU host can distinguish "no GPU"
		// from a real failure and simply skip GPU evidence.
		if _, ok := err.(interface{ Unwrap() error }); ok || err == gpuattest.ErrUnavailable {
			os.Exit(3)
		}
		os.Exit(1)
	}

	envelope := ev.Marshal()
	sum := ev.Sha256()
	sumHex := hex.EncodeToString(sum[:])

	if *write {
		if err := os.MkdirAll(*outDir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "gpu-attest: mkdir %s: %v\n", *outDir, err)
			os.Exit(1)
		}
		binPath := filepath.Join(*outDir, "gpu-evidence.bin")
		if err := writeAtomic(binPath, envelope, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "gpu-attest: write %s: %v\n", binPath, err)
			os.Exit(1)
		}
		shaPath := filepath.Join(*outDir, "gpu-evidence.sha256")
		if err := writeAtomic(shaPath, []byte(sumHex+"\n"), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "gpu-attest: write %s: %v\n", shaPath, err)
			os.Exit(1)
		}
	}

	if *printSummary {
		fmt.Fprintf(os.Stderr,
			"gpu-attest OK\n  gpu=%s\n  driver=%s vbios=%s cc_env=%d cc_feature=%d\n"+
				"  report=%dB certChain=%dB cec=%dB envelope=%dB\n  nonce=%s\n  sha256=%s\n",
			ev.GPUUUID, ev.DriverVersion, ev.VBIOSVersion, ev.CCEnvironment, ev.CCFeature,
			len(ev.AttestationReport), len(ev.AttestationCertChain), len(ev.CecReport),
			len(envelope), hex.EncodeToString(ev.Nonce[:]), sumHex)
	}
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
