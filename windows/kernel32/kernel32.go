package kernel32

import (
	"fmt"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

var Kernel32 = windows.NewLazySystemDLL("Kernel32.dll")

// GetConsoleWindowN Retrieves the window handle used by the console associated with the calling process.
// The "N" in the function name is for Native as it avoids using external packages
// https://docs.microsoft.com/en-us/windows/console/getconsolewindow
func GetConsoleWindowN() (handle *unsafe.Pointer, err error) {
	GetConsoleWindow := Kernel32.NewProc("GetConsoleWindow")
	// HWND WINAPI GetConsoleWindow(void);
	HWND, _, err := GetConsoleWindow.Call()
	if err != syscall.Errno(0) {
		err = fmt.Errorf("there was an error calling kernel32!GetConsoleWindow: %s", err)
		return
	}
	// I believe this misuse of unsafe.Pointer is required because the Windows API call returns a uintptr which could be garbage collected
	h := unsafe.Pointer(HWND)
	return &h, nil
}

// GetConsoleWindowG Retrieves the window handle used by the console associated with the calling process.
// The "G" at the end of the function name is for Golang because it uses the golang.org/x/sys/windows Go package
// https://docs.microsoft.com/en-us/windows/console/getconsolewindow
func GetConsoleWindowG() (handle windows.Handle, err error) {
	GetConsoleWindow := Kernel32.NewProc("GetConsoleWindow")
	// HWND WINAPI GetConsoleWindow(void);
	HWND, _, err := GetConsoleWindow.Call()
	if err != syscall.Errno(0) {
		err = fmt.Errorf("there was an error calling kernel32!GetConsoleWindow: %s", err)
		return
	}
	err = nil
	handle = windows.Handle(HWND)
	return
}
