# PKCS#11 ABI: Cross-Platform Considerations

This document explains the platform-specific C ABI issues encountered when
calling a PKCS#11 shared library from pure Go (no CGo), and how this plugin
solves them.

---

## 1. CK_ULONG size

The PKCS#11 standard defines `CK_ULONG` as C `unsigned long`. Its size depends
on the platform's data model:

| OS / Architecture | Data model | `sizeof(unsigned long)` |
|-------------------|------------|------------------------|
| Linux 64-bit      | LP64       | 8 bytes                |
| macOS 64-bit      | LP64       | 8 bytes                |
| Windows 64-bit    | **LLP64**  | **4 bytes**            |

On Windows, `long` stays 32-bit even on a 64-bit system. Getting this wrong
causes every integer argument to a PKCS#11 function to be misread.

**Fix:** platform-specific type aliases selected by build tags.

```go
// ck_ulong_unix.go  (darwin || linux || ...)
type CK_ULONG = uint   // 8 bytes on 64-bit

// ck_ulong_windows.go
type CK_ULONG = uint32 // 4 bytes
```

---

## 2. CK_ATTRIBUTE struct packing (Windows)

This was the harder problem, discovered during SoftHSM2 integration testing on
Windows.

### The C struct

```c
typedef struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;   /* CK_ULONG                  */
    CK_VOID_PTR       pValue; /* void*                     */
    CK_ULONG          ulValueLen;
} CK_ATTRIBUTE;
```

### Layout on LP64 Unix (natural alignment, no packing)

All fields are 8 bytes. No padding is needed:

```
offset  0 │ type        │ 8 bytes
offset  8 │ pValue      │ 8 bytes
offset 16 │ ulValueLen  │ 8 bytes
           ───────────────────────
sizeof = 24 bytes
```

Go's natural struct layout with `CK_ULONG = uint` matches exactly — no special
handling required.

### Layout on Windows LLP64 — without packing

`CK_ULONG` is 4 bytes, but `void*` is still 8 bytes (64-bit pointer). The C
compiler inserts 4 bytes of alignment padding before the pointer:

```
offset  0 │ type        │ 4 bytes
offset  4 │ (padding)   │ 4 bytes  ← inserted by compiler
offset  8 │ pValue      │ 8 bytes
offset 16 │ ulValueLen  │ 4 bytes
offset 20 │ (padding)   │ 4 bytes
           ───────────────────────
sizeof = 24 bytes
```

### What SoftHSM2 Windows actually uses — packed

SoftHSM2 for Windows is compiled with structure packing enabled, removing all
padding:

```
offset  0 │ type        │ 4 bytes
offset  4 │ pValue      │ 8 bytes  ← NO padding before pointer
offset 12 │ ulValueLen  │ 4 bytes
           ───────────────────────
sizeof = 16 bytes
```

### The bug

Go's natural `Attribute` struct (with `unsafe.Pointer` for the value field) has
`Value` at offset 8 and `ValueLen` at offset 16. SoftHSM2 expects `pValue` at
offset 4 and writes `ulValueLen` at offset 12.

Consequence observed during testing:

```
C_GetAttributeValue → rv=0x0 (CKR_OK), but ValueLen=0
```

The DLL wrote the correct length (4) to offset 12, but Go read `ValueLen` from
offset 16 which was still 0. Separately, `C_FindObjectsInit` read `pValue` from
offset 4 (the padding bytes, value zero → NULL pointer), causing all object
searches to return 0 results even though objects existed.

### The fix

Replace `unsafe.Pointer` with `[8]byte` for the value field. A byte array has
alignment 1, so Go inserts no padding before it:

```go
// types_windows.go
type Attribute struct {
    Type     CK_ULONG  // offset  0, 4 bytes
    _val     [8]byte   // offset  4, 8 bytes  ← alignment 1, no padding
    ValueLen CK_ULONG  // offset 12, 4 bytes
}
// sizeof = 16 bytes  ✓
```

The pointer is stored and retrieved via unsafe casting:

```go
func (a *Attribute) setValuePtr(p unsafe.Pointer) {
    *(*unsafe.Pointer)(unsafe.Pointer(&a._val[0])) = p
}
```

Unix uses the natural struct layout unchanged:

```go
// types_unix.go
type Attribute struct {
    Type     CK_ULONG       // 8 bytes
    _val     unsafe.Pointer // 8 bytes (no padding needed)
    ValueLen CK_ULONG       // 8 bytes
}
// sizeof = 24 bytes  ✓
```

---

## 3. CK_MECHANISM struct

`CK_MECHANISM` has the same field pattern (`CK_ULONG` + pointer + `CK_ULONG`)
and is subject to the same packing issue. The same `[8]byte` fix is applied in
`types_windows.go`.

For the mechanisms this plugin uses (`CKM_ECDSA`, `CKM_RSA_PKCS`), the
parameter pointer is always NULL and the length is always 0, so the padding
bytes happen to be zero in practice. The fix is applied anyway for correctness.

---

## 4. Diagnostic method

The packing issue was confirmed by dumping the raw bytes of an `Attribute`
struct before and after a `C_GetAttributeValue` call:

```
before: 000000000000000000000000000000000000000000000000
after:  000000000000000000000000 04000000 0000000000000000
                                ^offset 12 = 4 (correct length written by C)
ValueLen (offset 16) = 0        ^Go read here → still 0
```

The C function wrote `4` (the size of `CK_ULONG`) to offset 12. Go read
`ValueLen` from offset 16, which was untouched.

---

## 5. Summary

| Issue | Root cause | Fix |
|-------|-----------|-----|
| `CK_ULONG` wrong size on Windows | LLP64: `unsigned long` = 4 bytes | `ck_ulong_windows.go`: `type CK_ULONG = uint32` |
| `CK_ATTRIBUTE` packing mismatch | SoftHSM2 Windows compiled with packed structs | `types_windows.go`: `[8]byte` field avoids Go's pointer alignment padding |
| `C_FindObjectsInit` returns 0 objects | `pValue` read from offset 4 (padding) instead of 8 | Same fix above |
