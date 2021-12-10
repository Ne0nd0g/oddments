package kernel32

import (
	// Standard
	"fmt"
	"syscall"
	"unsafe"

	// X Packages
	"golang.org/x/sys/windows"
)

var Kernel32 = windows.NewLazySystemDLL("Kernel32.dll")

// CloseHandleN closes an open object handle
// The "N" in the function name is for Native as it avoids using external packages
// https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
func CloseHandleN(handle *unsafe.Pointer) (err error) {
	CloseHandle := Kernel32.NewProc("CloseHandle")

	// BOOL CloseHandle(
	//  [in] HANDLE hObject
	//);

	ret, _, err := CloseHandle.Call(uintptr(*handle))
	if err != syscall.Errno(0) || ret == 0 {
		err = fmt.Errorf("there was an error calling Kernel32!CloseHandle with return code %d: %s", ret, err)
		return
	}
	return nil
}

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

// GetCurrentProcessN retrieves a pseudo handle for the current process.
// The "N" in the function name is for Native as it avoids using external packages
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
func GetCurrentProcessN() (hProc *unsafe.Pointer, err error) {
	GetCurrentProcess := Kernel32.NewProc("GetCurrentProcess")

	// HANDLE GetCurrentProcess();
	handle, _, err := GetCurrentProcess.Call()
	if err != syscall.Errno(0) {
		err = fmt.Errorf("there was an error calling kernel32!GetCurrentProcess: %s", err)
		return
	}

	// I believe this misuse of unsafe.Pointer is required because the Windows API call returns a uintptr which could be garbage collected
	pHandle := unsafe.Pointer(handle)

	return &pHandle, nil
}

// GetCurrentThreadN Retrieves a pseudo handle for the calling thread.
// The "N" in the function name is for Native as it avoids using external packages
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthread
func GetCurrentThreadN() (hThread *unsafe.Pointer, err error) {
	GetCurrentThread := Kernel32.NewProc("GetCurrentThread")

	handle, _, err := GetCurrentThread.Call()
	if err != syscall.Errno(0) {
		err = fmt.Errorf("there was an error calling Kernel32!GetCurrentThread(): %s", err)
		return
	}
	// I believe this misuse of unsafe.Pointer is required because the Windows API call returns a uintptr which could be garbage collected
	tHandle := unsafe.Pointer(handle)
	return &tHandle, nil
}

// OpenProcessG Opens an existing local process object and returns a handle to it
// The "G" at the end of the function name is for Golang because it uses the golang.org/x/sys/windows Go package
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
func OpenProcessG(ProcessId uint32, DesiredAccess uint32, InheritHandle bool) (handle windows.Handle, err error) {
	handle, err = windows.OpenProcess(DesiredAccess, InheritHandle, ProcessId)
	if err != nil {
		err = fmt.Errorf("there was an error calling OpenProcess: %s", err)
	}
	return
}

// OpenProcessN Opens an existing local process object and returns a handle to it
// The "N" in the function name is for Native as it avoids using external packages
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
func OpenProcessN(ProcessId uint32, DesiredAccess uint32, InheritHandle bool) (hProc *unsafe.Pointer, err error) {
	OpenProcess := Kernel32.NewProc("OpenProcess")

	// HANDLE OpenProcess(
	//  [in] DWORD dwDesiredAccess,
	//  [in] BOOL  bInheritHandle,
	//  [in] DWORD dwProcessId
	//);

	var bInheritHandle int
	if InheritHandle {
		bInheritHandle = 1
	}

	handle, _, err := OpenProcess.Call(uintptr(DesiredAccess), uintptr(bInheritHandle), uintptr(ProcessId))
	if err != syscall.Errno(0) {
		err = fmt.Errorf("there was an error calling Kernel32!OpenProcess: %s", err)
		return
	}
	// I believe this misuse of unsafe.Pointer is required because the Windows API call returns a uintptr which could be garbage collected
	pHandle := unsafe.Pointer(handle)
	return &pHandle, nil
}
