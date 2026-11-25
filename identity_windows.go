//go:build windows

package licensekit

import (
	"errors"
	"syscall"
	"unsafe"
)

const keyWow6464Key = 0x0100 // KEY_WOW64_64KEY: read the 64-bit view from 32-bit apps too

// systemIdentity reads HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
// using only the standard library.
func systemIdentity() (string, error) {
	path, _ := syscall.UTF16PtrFromString(`SOFTWARE\Microsoft\Cryptography`)
	var key syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, path, 0, syscall.KEY_QUERY_VALUE|keyWow6464Key, &key); err != nil {
		return "", err
	}
	defer syscall.RegCloseKey(key)
	name, _ := syscall.UTF16PtrFromString("MachineGuid")
	var typ, size uint32
	if err := syscall.RegQueryValueEx(key, name, nil, &typ, nil, &size); err != nil {
		return "", err
	}
	if typ != syscall.REG_SZ || size == 0 || size > 1024 {
		return "", errors.New("unexpected MachineGuid value")
	}
	buf := make([]uint16, size/2+1)
	if err := syscall.RegQueryValueEx(key, name, nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &size); err != nil {
		return "", err
	}
	return parseUUID(syscall.UTF16ToString(buf))
}
