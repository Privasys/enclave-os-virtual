// Copyright (c) 2018 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// Privasys: the amd64 assembly of this package is removed and these pure-Go
// implementations are used on every platform. The AES-GCM-SIV assembly
// faulted (SIGSEGV, which no recover can catch) decrypting NTS replies from
// some servers, taking the whole process down.

package siv

func newGCM(key []byte) aead { return newGCMGeneric(key) }
