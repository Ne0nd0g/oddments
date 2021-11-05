// +build windows

package process

import (
	"fmt"
	"golang.org/x/sys/windows"
	"strings"
	"syscall"
	"unsafe"
)

// PROCESS_ Process Security and Access Rights
// https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
const (
	PROCESS_QUERY_INFORMATION uint32 = 0x0400
)

const (
	LOGON_WITH_PROFILE        uint32 = 0x1
	LOGON_NETCREDENTIALS_ONLY uint32 = 0x2
)

// OpenProcessG Opens an existing local process object and returns a handle to it
// The "G" at the end of the function name is for Golang because it uses the golang.org/x/sys/windows Go package
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
func OpenProcessG(pid uint32) (handle windows.Handle, err error) {
	handle, err = windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, true, pid)
	if err != nil {
		err = fmt.Errorf("there was an error calling OpenProcess: %s", err)
	}
	return
}

// OpenProcessN Opens an existing local process object and returns a handle to it
// The "N" in the function name is for Native as it avoids using external packages
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
func OpenProcessN(ProcessId uint32, DesiredAccess uint32, InheritHandle bool) (hProc *unsafe.Pointer, err error) {

	Kernel32 := windows.NewLazySystemDLL("Kernel32.dll")
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

// CreateProcessWithLogonG creates a new process and its primary thread. Then the new process runs the specified
// executable file in the security context of the specified credentials (user, domain, and password).
// It can optionally load the user profile for a specified user.
// The "G" at the end of the function name is for Golang because it uses the golang.org/x/sys/windows Go package
// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw
func CreateProcessWithLogonG(username string, domain string, password string, application string, args string, logon uint32) (lpProcessInformation windows.ProcessInformation, err error) {
	if username == "" {
		err = fmt.Errorf("a username must be provided for the CreateProcessWithLogon call")
		return
	}

	if password == "" {
		err = fmt.Errorf("a password must be provided for the CreateProcessWithLogon call")
		return
	}

	if application == "" {
		err = fmt.Errorf("an application must be provided for the CreateProcessWithLogon call")
		return
	}

	// Check for UPN format (e.g., rastley@acme.com)
	if strings.Contains(username, "@") {
		temp := strings.Split(username, "@")
		username = temp[0]
		domain = temp[1]
	}

	// Check for domain format (e.g., ACME\rastley)
	if strings.Contains(username, "\\") {
		temp := strings.Split(username, "\\")
		username = temp[1]
		domain = temp[0]
	}

	// Check for an empty or missing domain; used with local user accounts
	if domain == "" {
		domain = "."
	}

	// Convert the username to a LPCWSTR
	lpUsername, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		err = fmt.Errorf("there was an error converting the username \"%s\" to LPCWSTR: %s", username, err)
		return
	}

	// Convert the domain to a LPCWSTR
	lpDomain, err := syscall.UTF16PtrFromString(domain)
	if err != nil {
		err = fmt.Errorf("there was an error converting the domain \"%s\" to LPCWSTR: %s", domain, err)
		return
	}

	// Convert the password to a LPCWSTR
	lpPassword, err := syscall.UTF16PtrFromString(password)
	if err != nil {
		err = fmt.Errorf("there was an error converting the password \"%s\" to LPCWSTR: %s", password, err)
		return
	}

	// Convert the application to a LPCWSTR
	lpApplicationName, err := syscall.UTF16PtrFromString(application)
	if err != nil {
		err = fmt.Errorf("there was an error converting the application name \"%s\" to LPCWSTR: %s", application, err)
		return
	}

	// Convert the program to a LPCWSTR
	lpCommandLine, err := syscall.UTF16PtrFromString(args)
	if err != nil {
		err = fmt.Errorf("there was an error converting the application arguments \"%s\" to LPCWSTR: %s", args, err)
		return
	}

	lpStartupInfo := &windows.StartupInfo{}
	//lpProcessInformation := &windows.ProcessInformation{}

	Advapi32 := windows.NewLazySystemDLL("Advapi32.dll")
	CreateProcessWithLogon := Advapi32.NewProc("CreateProcessWithLogonW")

	// BOOL CreateProcessWithLogonW(
	//  [in]                LPCWSTR               lpUsername,
	//  [in, optional]      LPCWSTR               lpDomain,
	//  [in]                LPCWSTR               lpPassword,
	//  [in]                DWORD                 dwLogonFlags,
	//  [in, optional]      LPCWSTR               lpApplicationName,
	//  [in, out, optional] LPWSTR                lpCommandLine,
	//  [in]                DWORD                 dwCreationFlags,
	//  [in, optional]      LPVOID                lpEnvironment,
	//  [in, optional]      LPCWSTR               lpCurrentDirectory,
	//  [in]                LPSTARTUPINFOW        lpStartupInfo,
	//  [out]               LPPROCESS_INFORMATION lpProcessInformation
	//);
	_, _, err = CreateProcessWithLogon.Call(
		uintptr(unsafe.Pointer(lpUsername)),
		uintptr(unsafe.Pointer(lpDomain)),
		uintptr(unsafe.Pointer(lpPassword)),
		uintptr(logon),
		uintptr(unsafe.Pointer(lpApplicationName)),
		uintptr(unsafe.Pointer(lpCommandLine)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(lpStartupInfo)),
		uintptr(unsafe.Pointer(&lpProcessInformation)),
	)
	if err != syscall.Errno(0) {
		err = fmt.Errorf("there was an error calling CreateProcessWithLogon: %s", err)
		return
	}

	err = nil
	return
}

// CreateProcessWithLogonN creates a new process and its primary thread. Then the new process runs the specified
// executable file in the security context of the specified credentials (user, domain, and password).
// It can optionally load the user profile for a specified user.
// The "N" in the function name is for Native as it avoids using external packages
// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw
func CreateProcessWithLogonN(username string, domain string, password string, application string, args string, logon uint32) (lpProcessInformation windows.ProcessInformation, err error) {
	if username == "" {
		err = fmt.Errorf("a username must be provided for the CreateProcessWithLogon call")
		return
	}

	if password == "" {
		err = fmt.Errorf("a password must be provided for the CreateProcessWithLogon call")
		return
	}

	if application == "" {
		err = fmt.Errorf("an application must be provided for the CreateProcessWithLogon call")
		return
	}

	// Check for UPN format (e.g., rastley@acme.com)
	if strings.Contains(username, "@") {
		temp := strings.Split(username, "@")
		username = temp[0]
		domain = temp[1]
	}

	// Check for domain format (e.g., ACME\rastley)
	if strings.Contains(username, "\\") {
		temp := strings.Split(username, "\\")
		username = temp[1]
		domain = temp[0]
	}

	// Check for an empty or missing domain; used with local user accounts
	if domain == "" {
		domain = "."
	}

	// Convert the username to a LPCWSTR
	lpUsername, err := syscall.UTF16PtrFromString(username)
	if err != nil {
		err = fmt.Errorf("there was an error converting the username \"%s\" to LPCWSTR: %s", username, err)
		return
	}

	// Convert the domain to a LPCWSTR
	lpDomain, err := syscall.UTF16PtrFromString(domain)
	if err != nil {
		err = fmt.Errorf("there was an error converting the domain \"%s\" to LPCWSTR: %s", domain, err)
		return
	}

	// Convert the password to a LPCWSTR
	lpPassword, err := syscall.UTF16PtrFromString(password)
	if err != nil {
		err = fmt.Errorf("there was an error converting the password \"%s\" to LPCWSTR: %s", password, err)
		return
	}

	// Convert the application to a LPCWSTR
	lpApplicationName, err := syscall.UTF16PtrFromString(application)
	if err != nil {
		err = fmt.Errorf("there was an error converting the application name \"%s\" to LPCWSTR: %s", application, err)
		return
	}

	// Convert the program to a LPCWSTR
	lpCommandLine, err := syscall.UTF16PtrFromString(args)
	if err != nil {
		err = fmt.Errorf("there was an error converting the application arguments \"%s\" to LPCWSTR: %s", args, err)
		return
	}

	lpStartupInfo := &StartupInfo{}
	//lpProcessInformation := &windows.ProcessInformation{}

	Advapi32 := windows.NewLazySystemDLL("Advapi32.dll")
	CreateProcessWithLogon := Advapi32.NewProc("CreateProcessWithLogonW")

	// BOOL CreateProcessWithLogonW(
	//  [in]                LPCWSTR               lpUsername,
	//  [in, optional]      LPCWSTR               lpDomain,
	//  [in]                LPCWSTR               lpPassword,
	//  [in]                DWORD                 dwLogonFlags,
	//  [in, optional]      LPCWSTR               lpApplicationName,
	//  [in, out, optional] LPWSTR                lpCommandLine,
	//  [in]                DWORD                 dwCreationFlags,
	//  [in, optional]      LPVOID                lpEnvironment,
	//  [in, optional]      LPCWSTR               lpCurrentDirectory,
	//  [in]                LPSTARTUPINFOW        lpStartupInfo,
	//  [out]               LPPROCESS_INFORMATION lpProcessInformation
	//);
	_, _, err = CreateProcessWithLogon.Call(
		uintptr(unsafe.Pointer(lpUsername)),
		uintptr(unsafe.Pointer(lpDomain)),
		uintptr(unsafe.Pointer(lpPassword)),
		uintptr(logon),
		uintptr(unsafe.Pointer(lpApplicationName)),
		uintptr(unsafe.Pointer(lpCommandLine)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(lpStartupInfo)),
		uintptr(unsafe.Pointer(&lpProcessInformation)),
	)
	if err != syscall.Errno(0) {
		err = fmt.Errorf("there was an error calling CreateProcessWithLogon: %s", err)
		return
	}

	err = nil
	return
}

// GetCurrentProcessN retrieves a pseudo handle for the current process.
// The "N" in the function name is for Native as it avoids using external packages
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
func GetCurrentProcessN() (hProc *unsafe.Pointer, err error) {
	Kernel32 := windows.NewLazySystemDLL("Kernel32.dll")
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
	Kernel32 := windows.NewLazySystemDLL("Kernel32.dll")
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

// GetCurrentProcessTokenN retrieves a pseudo-handle that you can use as a shorthand way to refer to the access token associated with a process.
// You do not need to close the pseudo-handle when you no longer need it.
// The "N" in the function name is for Native as it avoids using external packages
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocesstoken
func GetCurrentProcessTokenN() *unsafe.Pointer {
	handle := unsafe.Pointer(^uintptr(4 - 1))
	return &handle
}

// GetCurrentThreadTokenN retrieves a pseudo-handle that you can use as a shorthand way to refer to the impersonation token that was assigned to the current thread.
// You do not need to close the pseudo-handle when you no longer need it.
// The "N" in the function name is for Native as it avoids using external packages
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthreadtoken
func GetCurrentThreadTokenN() *unsafe.Pointer {
	handle := unsafe.Pointer(^uintptr(5 - 1))
	return &handle
}

// GetCurrentThreadEffectiveTokenN retrieves a pseudo-handle that you can use as a shorthand way to refer to the
// token that is currently in effect for the thread, which is the thread token if one exists and the process token otherwise.
// The "N" in the function name is for Native as it avoids using external packages
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthreadeffectivetoken
func GetCurrentThreadEffectiveTokenN() *unsafe.Pointer {
	handle := unsafe.Pointer(^uintptr(6 - 1))
	return &handle
}

// StartupInfo specifies the window station, desktop, standard handles, and appearance of the main window for a process at creation time.
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfoa
// https://pkg.go.dev/golang.org/x/sys/windows#StartupInfo
type StartupInfo struct {
	Cb            uint32
	_             *uint16
	Desktop       *uint16
	Title         *uint16
	X             uint32
	Y             uint32
	XSize         uint32
	YSize         uint32
	XCountChars   uint32
	YCountChars   uint32
	FillAttribute uint32
	Flags         uint32
	ShowWindow    uint16
	_             uint16
	_             *byte
	StdInput      uintptr
	StdOutput     uintptr
	StdErr        uintptr
}

// ProcessInformation Contains information about a newly created process and its primary thread.
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information
// https://pkg.go.dev/golang.org/x/sys/windows#ProcessInformation
type ProcessInformation struct {
	Process   uintptr
	Thread    uintptr
	ProcessId uint32
	ThreadId  uint32
}
