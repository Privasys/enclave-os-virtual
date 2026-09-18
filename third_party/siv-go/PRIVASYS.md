Privasys copy of github.com/secure-io/siv-go at 5ff40651e2c4 (MIT, see
LICENSE), with the amd64 assembly removed: the pure-Go AES-SIV-CMAC and
AES-GCM-SIV implementations are used on every platform. The AES-GCM-SIV
assembly faulted (SIGSEGV) decrypting NTS replies from some servers.

