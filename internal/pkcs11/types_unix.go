//go:build darwin || linux || freebsd || netbsd

package pkcs11

import "unsafe"

// Attribute mirrors CK_ATTRIBUTE on LP64 Unix systems.
// On LP64, CK_ULONG is 8 bytes, so all three fields are naturally 8-byte aligned
// with no padding required:
//
//	type(8) | pValue(8) | ulValueLen(8) = 24 bytes
type Attribute struct {
	Type     CK_ULONG
	_val     unsafe.Pointer
	ValueLen CK_ULONG
}

func (a *Attribute) setValuePtr(p unsafe.Pointer) {
	a._val = p
}

// newAttr constructs an Attribute with the given type, value pointer, and length.
func newAttr(typ CK_ULONG, value unsafe.Pointer, valueLen CK_ULONG) Attribute {
	return Attribute{Type: typ, _val: value, ValueLen: valueLen}
}

// Mechanism mirrors CK_MECHANISM on LP64 Unix:
//
//	mechanism(8) | pParameter(8) | ulParameterLen(8) = 24 bytes
type Mechanism struct {
	Mechanism    CK_ULONG
	_param       unsafe.Pointer
	ParameterLen CK_ULONG
}
