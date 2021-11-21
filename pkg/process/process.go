// +build windows

// Package process contains wrapper functions that interact with Windows processes
// No DLLs should be loaded in this package

package process

import (
	// Standard
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	// X Packages
	"golang.org/x/sys/windows"

	// Oddments Internal
	"github.com/Ne0nd0g/oddments/windows/advapi32"
)

// CreateProcessWithLogonG creates a new process and its primary thread. Then the new process runs the specified
// executable file in the security context of the specified credentials (user, domain, and password).
// It can optionally load the user profile for a specified user.
// This wrapper function performs validation checks on input arguments and converts them to the necessary type
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

	lpCurrentDirectory := uint16(0)
	lpStartupInfo := windows.StartupInfo{}

	err = advapi32.CreateProcessWithLogonG(
		lpUsername,
		lpDomain,
		lpPassword,
		logon,
		lpApplicationName,
		lpCommandLine,
		0,
		0,
		&lpCurrentDirectory,
		&lpStartupInfo,
		&lpProcessInformation,
	)
	return
}

// CreateProcessWithLogonN creates a new process and its primary thread. Then the new process runs the specified
// executable file in the security context of the specified credentials (user, domain, and password).
// It can optionally load the user profile for a specified user.
// This wrapper function performs validation checks on input arguments and converts them to the necessary type
// The "N" in the function name is for Native as it avoids using external packages
// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw
func CreateProcessWithLogonN(username string, domain string, password string, application string, args string, logon uint32) (lpProcessInformation advapi32.ProcessInformation, err error) {
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

	lpStartupInfo := advapi32.StartupInfo{}
	//lpProcessInformation := &windows.ProcessInformation{}
	lpCurrentDirectory := uint16(0)

	err = advapi32.CreateProcessWithLogonN(
		lpUsername,
		lpDomain,
		lpPassword,
		logon,
		lpApplicationName,
		lpCommandLine,
		0,
		0,
		&lpCurrentDirectory,
		&lpStartupInfo,
		&lpProcessInformation,
	)
	return
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
