//go:build darwin || linux || freebsd || netbsd

package pkcs11

// CK_ULONG is the PKCS#11 unsigned long type.
// On LP64 systems (Linux, macOS) unsigned long is 8 bytes on 64-bit platforms,
// matching Go's uint.
type CK_ULONG = uint
