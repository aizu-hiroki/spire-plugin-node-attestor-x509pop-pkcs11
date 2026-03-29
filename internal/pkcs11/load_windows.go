//go:build windows

package pkcs11

import "syscall"

func openLibrary(path string) (uintptr, error) {
	h, err := syscall.LoadLibrary(path)
	return uintptr(h), err
}

func closeLibrary(handle uintptr) {
	syscall.FreeLibrary(syscall.Handle(handle))
}

func openSymbol(lib uintptr, name string) (uintptr, error) {
	return syscall.GetProcAddress(syscall.Handle(lib), name)
}
