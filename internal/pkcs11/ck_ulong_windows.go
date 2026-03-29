//go:build windows

package pkcs11

// CK_ULONG is the PKCS#11 unsigned long type.
// Windows uses the LLP64 data model: unsigned long is 32 bits even on 64-bit
// Windows, so CK_ULONG must be uint32 to match the PKCS#11 ABI.
type CK_ULONG = uint32
