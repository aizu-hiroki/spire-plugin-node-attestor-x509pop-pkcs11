//go:build darwin || linux || freebsd || netbsd

package pkcs11

import "github.com/ebitengine/purego"

func openLibrary(path string) (uintptr, error) {
	return purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_GLOBAL)
}

func closeLibrary(handle uintptr) {
	purego.Dlclose(handle)
}

func openSymbol(lib uintptr, name string) (uintptr, error) {
	return purego.Dlsym(lib, name)
}
