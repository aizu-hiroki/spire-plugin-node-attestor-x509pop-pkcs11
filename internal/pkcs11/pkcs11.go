// Package pkcs11 provides a pure-Go (no CGo) PKCS#11 client that dynamically
// loads the PKCS#11 shared library at runtime.
//
// On Unix (macOS, Linux) it uses purego for Dlopen/Dlsym.
// On Windows it uses syscall.LoadLibrary/GetProcAddress.
// Function calls are dispatched via purego.RegisterFunc on all platforms.
//
// Only the subset of PKCS#11 needed for signing operations is implemented.
package pkcs11

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/ebitengine/purego"
)

// PKCS#11 constants.
const (
	CKF_SERIAL_SESSION = 0x00000004
	CKF_RW_SESSION     = 0x00000002

	CKU_USER = 1

	CKA_CLASS          = 0x00000000
	CKA_ID             = 0x00000102
	CKA_LABEL          = 0x00000003
	CKA_KEY_TYPE       = 0x00000100
	CKA_EC_PARAMS      = 0x00000180
	CKA_EC_POINT       = 0x00000181
	CKA_MODULUS        = 0x00000120
	CKA_PUBLIC_EXPONENT = 0x00000122

	CKO_PRIVATE_KEY = 0x00000003
	CKO_PUBLIC_KEY  = 0x00000002

	CKK_EC  = 0x00000003
	CKK_RSA = 0x00000000

	CKM_ECDSA    = 0x00001041
	CKM_RSA_PKCS = 0x00000001

	CKR_OK = 0
)


// Module represents a loaded PKCS#11 module.
type Module struct {
	lib                 uintptr
	C_Initialize        func(initArgs uintptr) CK_ULONG
	C_Finalize          func(reserved uintptr) CK_ULONG
	C_GetSlotList       func(tokenPresent byte, slotList *CK_ULONG, count *CK_ULONG) CK_ULONG
	C_GetTokenInfo      func(slotID CK_ULONG, info uintptr) CK_ULONG
	C_OpenSession       func(slotID CK_ULONG, flags CK_ULONG, app uintptr, notify uintptr, session *CK_ULONG) CK_ULONG
	C_CloseSession      func(session CK_ULONG) CK_ULONG
	C_Login             func(session CK_ULONG, userType CK_ULONG, pin *byte, pinLen CK_ULONG) CK_ULONG
	C_Logout            func(session CK_ULONG) CK_ULONG
	C_FindObjectsInit   func(session CK_ULONG, template *Attribute, count CK_ULONG) CK_ULONG
	C_FindObjects       func(session CK_ULONG, objects *CK_ULONG, maxCount CK_ULONG, objectCount *CK_ULONG) CK_ULONG
	C_FindObjectsFinal  func(session CK_ULONG) CK_ULONG
	C_GetAttributeValue func(session CK_ULONG, object CK_ULONG, template *Attribute, count CK_ULONG) CK_ULONG
	C_SignInit          func(session CK_ULONG, mechanism *Mechanism, key CK_ULONG) CK_ULONG
	C_Sign              func(session CK_ULONG, data *byte, dataLen CK_ULONG, signature *byte, signatureLen *CK_ULONG) CK_ULONG
}

// Load opens the PKCS#11 shared library and resolves the C_* function symbols.
func Load(path string) (*Module, error) {
	lib, err := openLibrary(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load PKCS#11 library %s: %w", path, err)
	}

	m := &Module{lib: lib}

	reg := func(name string, fn interface{}) {
		if err != nil {
			return
		}
		sym, e := openSymbol(lib, name)
		if e != nil {
			err = fmt.Errorf("symbol %s not found: %w", name, e)
			return
		}
		purego.RegisterFunc(fn, sym)
	}

	reg("C_Initialize", &m.C_Initialize)
	reg("C_Finalize", &m.C_Finalize)
	reg("C_GetSlotList", &m.C_GetSlotList)
	reg("C_GetTokenInfo", &m.C_GetTokenInfo)
	reg("C_OpenSession", &m.C_OpenSession)
	reg("C_CloseSession", &m.C_CloseSession)
	reg("C_Login", &m.C_Login)
	reg("C_Logout", &m.C_Logout)
	reg("C_FindObjectsInit", &m.C_FindObjectsInit)
	reg("C_FindObjects", &m.C_FindObjects)
	reg("C_FindObjectsFinal", &m.C_FindObjectsFinal)
	reg("C_GetAttributeValue", &m.C_GetAttributeValue)
	reg("C_SignInit", &m.C_SignInit)
	reg("C_Sign", &m.C_Sign)

	if err != nil {
		closeLibrary(lib)
		return nil, err
	}

	return m, nil
}

// Close finalizes and unloads the PKCS#11 module.
func (m *Module) Close() {
	if m.lib != 0 {
		m.C_Finalize(0)
		closeLibrary(m.lib)
		m.lib = 0
	}
}

// TokenInfo contains information about a PKCS#11 token.
type TokenInfo struct {
	Label        string
	Serial       string
	Manufacturer string
	Model        string
}

// tokenInfoRaw mirrors the C CK_TOKEN_INFO structure layout.
type tokenInfoRaw struct {
	Label          [32]byte
	ManufacturerID [32]byte
	Model          [16]byte
	SerialNumber   [16]byte
	_rest          [192]byte
}

func trimPadding(b []byte) string {
	end := len(b)
	for end > 0 && (b[end-1] == ' ' || b[end-1] == 0) {
		end--
	}
	return string(b[:end])
}

// GetTokenInfo retrieves the token information for the given slot.
func (m *Module) GetTokenInfo(slotID CK_ULONG) (*TokenInfo, error) {
	var raw tokenInfoRaw
	rv := m.C_GetTokenInfo(slotID, uintptr(unsafe.Pointer(&raw)))
	if rv != CKR_OK {
		return nil, fmt.Errorf("C_GetTokenInfo failed: 0x%x", rv)
	}
	return &TokenInfo{
		Label:        trimPadding(raw.Label[:]),
		Manufacturer: trimPadding(raw.ManufacturerID[:]),
		Model:        trimPadding(raw.Model[:]),
		Serial:       trimPadding(raw.SerialNumber[:]),
	}, nil
}

// GetSlotList returns the list of slot IDs with a token present.
func (m *Module) GetSlotList() ([]CK_ULONG, error) {
	var count CK_ULONG
	rv := m.C_GetSlotList(1, nil, &count)
	if rv != CKR_OK {
		return nil, fmt.Errorf("C_GetSlotList (count): 0x%x", rv)
	}
	if count == 0 {
		return nil, nil
	}
	slots := make([]CK_ULONG, count)
	rv = m.C_GetSlotList(1, &slots[0], &count)
	if rv != CKR_OK {
		return nil, fmt.Errorf("C_GetSlotList: 0x%x", rv)
	}
	return slots[:count], nil
}

// FindSlotByLabel finds the slot whose token label matches.
func (m *Module) FindSlotByLabel(label string) (CK_ULONG, error) {
	slots, err := m.GetSlotList()
	if err != nil {
		return 0, err
	}
	for _, slot := range slots {
		info, err := m.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		if info.Label == label {
			return slot, nil
		}
	}
	return 0, fmt.Errorf("token with label %q not found", label)
}

func buildFindTemplate(class CK_ULONG, keyID []byte, keyLabel string) ([]Attribute, [][]byte) {
	var keepAlive [][]byte
	var attrs []Attribute

	sz := int(unsafe.Sizeof(CK_ULONG(0)))
	classBytes := make([]byte, sz)
	if sz == 8 {
		binary.LittleEndian.PutUint64(classBytes, uint64(class))
	} else {
		binary.LittleEndian.PutUint32(classBytes, uint32(class))
	}
	keepAlive = append(keepAlive, classBytes)
	attrs = append(attrs, newAttr(CKA_CLASS, unsafe.Pointer(&classBytes[0]), CK_ULONG(len(classBytes))))

	if len(keyID) > 0 {
		id := make([]byte, len(keyID))
		copy(id, keyID)
		keepAlive = append(keepAlive, id)
		attrs = append(attrs, newAttr(CKA_ID, unsafe.Pointer(&id[0]), CK_ULONG(len(id))))
	}

	if keyLabel != "" {
		lb := []byte(keyLabel)
		keepAlive = append(keepAlive, lb)
		attrs = append(attrs, newAttr(CKA_LABEL, unsafe.Pointer(&lb[0]), CK_ULONG(len(lb))))
	}

	return attrs, keepAlive
}
