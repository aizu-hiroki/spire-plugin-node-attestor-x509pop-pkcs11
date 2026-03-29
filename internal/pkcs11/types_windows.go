//go:build windows

package pkcs11

import "unsafe"

// Attribute mirrors the CK_ATTRIBUTE struct as compiled by SoftHSM2 on Windows.
// SoftHSM2 is built with packing enabled, so there is NO alignment padding between
// the type field and the pValue pointer:
//
//	type(4) | pValue(8) | ulValueLen(4) = 16 bytes
//
// Go's natural layout would add 4 bytes of padding before the pointer, giving 24
// bytes — which causes C_GetAttributeValue / C_FindObjectsInit to read/write the
// wrong offsets.  Using a [8]byte array for the pointer field avoids the padding
// because byte arrays have alignment 1.
type Attribute struct {
	Type     CK_ULONG
	_val     [8]byte  // stores unsafe.Pointer at offset 4 (no padding before this)
	ValueLen CK_ULONG // offset 12
}

func (a *Attribute) setValuePtr(p unsafe.Pointer) {
	*(*unsafe.Pointer)(unsafe.Pointer(&a._val[0])) = p
}

// newAttr constructs an Attribute with the given type, value pointer, and length.
func newAttr(typ CK_ULONG, value unsafe.Pointer, valueLen CK_ULONG) Attribute {
	a := Attribute{Type: typ, ValueLen: valueLen}
	if value != nil {
		a.setValuePtr(value)
	}
	return a
}

// Mechanism mirrors CK_MECHANISM with Windows's packed layout:
//
//	mechanism(4) | pParameter(8) | ulParameterLen(4) = 16 bytes
type Mechanism struct {
	Mechanism    CK_ULONG
	_param       [8]byte
	ParameterLen CK_ULONG
}
