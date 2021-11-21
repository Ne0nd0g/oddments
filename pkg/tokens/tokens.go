// +build windows

// Package tokens contains wrapper functions that interact with Windows Access Tokens
// No DLLs should be loaded in this package

package tokens

import (
	// Standard
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	// X Packages
	"golang.org/x/sys/windows"

	// Oddments Internal
	"oddments/pkg/process"
	"oddments/windows/advapi32"
)

// AdjustTokenPrivilegesG enables or disables privileges in the specified access token.
// Enabling or disabling privileges in an access token requires TOKEN_ADJUST_PRIVILEGES access.
// The "G" at the end of the function name is for Golang because it uses the golang.org/x/sys/windows Go package
// https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
func AdjustTokenPrivilegesG(hToken windows.Token, disable bool, privilege string) (err error) {
	// Convert privilege to LPCSTRW
	lpName, err := syscall.UTF16PtrFromString(privilege)
	if err != nil {
		err = fmt.Errorf("there was an error converting the privilege \"%s\" to LPCWSTR: %s", privilege, err)
		return
	}

	// Look up the privilege LUID
	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, lpName, &luid)
	if err != nil {
		err = fmt.Errorf("there was an error calling windows.LookupPrivilegeValue for %s: %s", privilege, err)
		return
	}

	// Create the TOKEN_PRIVILEGES structure
	privileges := windows.Tokenprivileges{
		PrivilegeCount: 1,
	}
	privileges.Privileges[0].Luid = luid
	privileges.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
	if disable {
		privileges.Privileges[0].Attributes = windows.SE_PRIVILEGE_REMOVED
	}

	// Adjust
	err = windows.AdjustTokenPrivileges(hToken, false, &privileges, 0, nil, nil)
	if err != nil {
		err = fmt.Errorf("there was an error calling windows.AdjustTOkenPrivileges: %s", err)
		return
	}
	err = nil
	return
}

// CreateProcessWithTokenN creates a new process as the user associated with the passed in token
// This requires administrative privileges or at least the SE_IMPERSONATE_NAME privilege
func CreateProcessWithTokenN(token *unsafe.Pointer, application string, args string) (err error) {
	if application == "" {
		err = fmt.Errorf("a program must be provided for the CreateProcessWithToken call")
		return
	}

	// Verify that the calling process has the SE_IMPERSONATE_NAME privilege
	luid, err := advapi32.LookupPrivilegeValueN("SeImpersonatePrivilege")
	if err != nil {
		return
	}

	hasPriv, err := hasPrivilege(process.GetCurrentProcessTokenN(), luid)
	if err != nil {
		return fmt.Errorf("the provided access token does not have the SeImpersonatePrivilege and can't be used to create a process")
	}

	// TODO try to enable the priv before returning with an error
	if !hasPriv {
		return fmt.Errorf("the provided access token does not have the SeImpersonatePrivilege and therefore can't be used to call CreateProcessWithToken")
	}

	// TODO verify the provided token is a PRIMARY token
	// TODO verify the provided token has the TOKEN_QUERY, TOKEN_DUPLICATE, and TOKEN_ASSIGN_PRIMARY access rights

	// Convert the program to a LPCWSTR
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

	// BOOL CreateProcessWithTokenW(
	//  [in]                HANDLE                hToken,
	//  [in]                DWORD                 dwLogonFlags,
	//  [in, optional]      LPCWSTR               lpApplicationName,
	//  [in, out, optional] LPWSTR                lpCommandLine,
	//  [in]                DWORD                 dwCreationFlags,
	//  [in, optional]      LPVOID                lpEnvironment,
	//  [in, optional]      LPCWSTR               lpCurrentDirectory,
	//  [in]                LPSTARTUPINFOW        lpStartupInfo,
	//  [out]               LPPROCESS_INFORMATION lpProcessInformation
	//);

	lpCurrentDirectory := uint16(0)
	lpStartupInfo := &advapi32.StartupInfo{}
	lpProcessInformation := &advapi32.ProcessInformation{}

	err = advapi32.CreateProcessWithTokenN(
		token,
		advapi32.LOGON_NETCREDENTIALS_ONLY,
		lpApplicationName,
		lpCommandLine,
		0,
		0,
		&lpCurrentDirectory,
		lpStartupInfo,
		lpProcessInformation,
	)
	return
}

// EnablePrivilegeG is a meta function that enables the provided privilege for the current process
// The "G" at the end of the function name is for Golang because it uses the golang.org/x/sys/windows Go package
func EnablePrivilegeG(privilege string) (err error) {
	// Get handle to the current process
	hProc := windows.CurrentProcess()

	// Get token with adjust privileges
	var hToken windows.Token
	err = windows.OpenProcessToken(hProc, windows.TOKEN_ADJUST_PRIVILEGES, &hToken)
	if err != nil {
		err = fmt.Errorf("there was an error calling windows.OpenProcessToken: %s", err)
		return
	}

	return AdjustTokenPrivilegesG(hToken, false, privilege)
}

// GetTokenStatsG uses the GetTokenInformation Windows API call to gather information about the provided access token
// by retrieving the token's associated TOKEN_STATISTICS structure
// The "G" at the end of the function name is for Golang because it uses the golang.org/x/sys/windows Go package
// https://github.com/gentilkiwi/mimikatz/blob/e10bde5b16b747dc09ca5146f93f2beaf74dd17a/mimikatz/modules/kuhl_m_token.c#L181
func GetTokenStatsG(token windows.Token) (tokenStats advapi32.TOKEN_STATISTICS, err error) {
	// Determine the size needed for the structure
	// BOOL GetTokenInformation(
	//  [in]            HANDLE                  TokenHandle,
	//  [in]            TOKEN_INFORMATION_CLASS TokenInformationClass,
	//  [out, optional] LPVOID                  TokenInformation,
	//  [in]            DWORD                   TokenInformationLength,
	//  [out]           PDWORD                  ReturnLength
	//);
	var returnLength uint32
	err = windows.GetTokenInformation(token, windows.TokenStatistics, nil, 0, &returnLength)
	if err != nil && err != syscall.ERROR_INSUFFICIENT_BUFFER {
		err = fmt.Errorf("there was an error calling windows.GetTokenInformation: %s", err)
		return
	}

	// Make the call with the known size of the object
	info := bytes.NewBuffer(make([]byte, returnLength))
	var returnLength2 uint32
	err = windows.GetTokenInformation(token, windows.TokenStatistics, &info.Bytes()[0], returnLength, &returnLength2)
	if err != nil {
		err = fmt.Errorf("there was an error calling windows.GetTokenInformation: %s", err)
		return
	}

	err = binary.Read(info, binary.LittleEndian, &tokenStats)
	if err != nil {
		err = fmt.Errorf("there was an error reading binary into the TOKEN_STATISTICS structure: %s", err)
		return
	}
	return
}

// GetTokenStatsN calls GetTokenInformationN and marshals the data into a TOKEN_STATISTICS structure
// The "N" in the function name is for Native as it avoids using external packages
func GetTokenStatsN(token *unsafe.Pointer) (tokenStats advapi32.TOKEN_STATISTICS, err error) {
	var TokenStatistics uint32 = 10
	info, _, err := advapi32.GetTokenInformationN(token, TokenStatistics)
	if err != nil {
		return
	}

	err = binary.Read(info, binary.LittleEndian, &tokenStats)
	if err != nil {
		err = fmt.Errorf("there was an error reading binary into the TOKEN_STATISTICS structure: %s", err)
		return
	}
	return
}

// GetUserNameExG retrieves the name of the user or other security principal associated with the calling thread
// The "G" at the end of the function name is for Golang because it uses the golang.org/x/sys/windows Go package
// https://docs.microsoft.com/en-us/windows/win32/api/secext/nf-secext-getusernameexa
func GetUserNameExG(format uint32) (username string, err error) {
	// BOOLEAN SEC_ENTRY GetUserNameExA(
	//  [in]      EXTENDED_NAME_FORMAT NameFormat,
	//  [out]     LPSTR                lpNameBuffer,
	//  [in, out] PULONG               nSize
	//);

	lpNameBuffer := make([]uint16, 100)
	nSize := uint32(100)

	err = windows.GetUserNameEx(format, &lpNameBuffer[0], &nSize)
	if err != nil {
		err = fmt.Errorf("there was an error calling windows.GetUserNameEx: %s", err)
		return
	}
	username = windows.UTF16ToString(lpNameBuffer)
	return
}

// hasPrivilege checks the provided access token to see if it contains the provided privilege
func hasPrivilege(token *unsafe.Pointer, privilege advapi32.LUID) (bool, error) {
	// Get privileges for the passed in access token
	TokenInformation, _, err := advapi32.GetTokenInformationN(token, advapi32.TokenPrivileges)
	if err != nil {
		return false, fmt.Errorf("there was an error calling GetTokenInformationN: %s", err)
	}

	var privilegeCount uint32
	err = binary.Read(TokenInformation, binary.LittleEndian, &privilegeCount)
	if err != nil {
		return false, fmt.Errorf("there was an error reading TokenPrivileges bytes to privilegeCount: %s", err)
	}

	// Read in the LUID and Attributes
	var privs []advapi32.LUID_AND_ATTRIBUTES
	for i := 1; i <= int(privilegeCount); i++ {
		var priv advapi32.LUID_AND_ATTRIBUTES
		err = binary.Read(TokenInformation, binary.LittleEndian, &priv)
		if err != nil {
			return false, fmt.Errorf("there was an error reading LUIDAttributes to bytes: %s", err)
		}
		privs = append(privs, priv)
	}

	// Iterate over provided token's privileges and return true if it is present
	for _, priv := range privs {
		if priv.Luid == privilege {
			return true, nil
		}
	}
	return false, nil
}

// impersonationToString converts a SECURITY_IMPERSONATION_LEVEL uint32 value to it's associated string
func impersonationToString(level uint32) string {
	switch level {
	case advapi32.SecurityAnonymous:
		return "Anonymous"
	case advapi32.SecurityIdentification:
		return "Identification"
	case advapi32.SecurityImpersonation:
		return "Impersonation"
	case advapi32.SecurityDelegation:
		return "Delegation"
	default:
		return fmt.Sprintf("unknown SECURITY_IMPERSONATION_LEVEL: %d", level)
	}
}

// IntegrityLevelToString converts an access token integrity level to a string
// https://docs.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
func IntegrityLevelToString(level uint32) string {
	switch level {
	case 0x00000000: // SECURITY_MANDATORY_UNTRUSTED_RID
		return "Untrusted"
	case 0x00001000: // SECURITY_MANDATORY_LOW_RID
		return "Low"
	case 0x00002000: // SECURITY_MANDATORY_MEDIUM_RID
		return "Medium"
	case 0x00002100: // SECURITY_MANDATORY_MEDIUM_PLUS_RID
		return "Medium High"
	case 0x00003000: // SECURITY_MANDATORY_HIGH_RID
		return "High"
	case 0x00004000: // SECURITY_MANDATORY_SYSTEM_RID
		return "System"
	case 0x00005000: // SECURITY_MANDATORY_PROTECTED_PROCESS_RID
		return "Protected Process"
	default:
		return fmt.Sprintf("Uknown integrity level: %d", level)
	}
}

// LogonUserG creates a new logon session for the user according to the provided logon type and returns a Windows access
// token for that logon session
// The "G" at the end of the function name is for Golang because it uses the golang.org/x/sys/windows Go package
// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw
func LogonUserG(user string, password string, domain string, logonType uint32, logonProvider uint32) (hToken windows.Token, err error) {
	if user == "" {
		err = fmt.Errorf("a username must be provided for the LogonUser call")
		return
	}

	if password == "" {
		err = fmt.Errorf("a password must be provided for the LogonUser call")
		return
	}

	if logonType <= 0 {
		err = fmt.Errorf("an invalid logonType was provided to the LogonUser call: %d", logonType)
		return
	}

	// Check for UPN format (e.g., rastley@acme.com)
	if strings.Contains(user, "@") {
		temp := strings.Split(user, "@")
		user = temp[0]
		domain = temp[1]
	}

	// Check for domain format (e.g., ACME\rastley)
	if strings.Contains(user, "\\") {
		temp := strings.Split(user, "\\")
		user = temp[1]
		domain = temp[0]
	}

	// Check for an empty or missing domain; used with local user accounts
	if domain == "" {
		domain = "."
	}

	// Convert username to LPCWSTR
	pUser, err := syscall.UTF16PtrFromString(user)
	if err != nil {
		err = fmt.Errorf("there was an error converting the username \"%s\" to LPCWSTR: %s", user, err)
		return
	}

	// Convert the domain to LPCWSTR
	pDomain, err := syscall.UTF16PtrFromString(domain)
	if err != nil {
		err = fmt.Errorf("there was an error converting the domain \"%s\" to LPCWSTR: %s", domain, err)
		return
	}

	// Convert the password to LPCWSTR
	pPassword, err := syscall.UTF16PtrFromString(password)
	if err != nil {
		err = fmt.Errorf("there was an error converting the password \"%s\" to LPCWSTR: %s", password, err)
		return
	}

	token, err := advapi32.LogonUser(pUser, pDomain, pPassword, logonType, logonProvider)
	if err != nil {
		return
	}

	// Convert *unsafe.Pointer to windows.Token
	// windows.Token -> windows.Handle -> uintptr
	hToken = (windows.Token)(*token)
	return
}

// LogonUserN creates a new logon session for the user according to the provided logon type and returns a Windows access
// token for that logon session
// The "N" in the function name is for Native as it avoids using external packages
// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw
func LogonUserN(user string, password string, domain string, logonType uint32, logonProvider uint32) (hToken *unsafe.Pointer, err error) {
	if user == "" {
		err = fmt.Errorf("a username must be provided for the LogonUser call")
		return
	}

	if password == "" {
		err = fmt.Errorf("a password must be provided for the LogonUser call")
		return
	}

	if logonType <= 0 {
		err = fmt.Errorf("an invalid logonType was provided to the LogonUser call: %d", logonType)
		return
	}

	// Check for UPN format (e.g., rastley@acme.com)
	if strings.Contains(user, "@") {
		temp := strings.Split(user, "@")
		user = temp[0]
		domain = temp[1]
	}

	// Check for domain format (e.g., ACME\rastley)
	if strings.Contains(user, "\\") {
		temp := strings.Split(user, "\\")
		user = temp[1]
		domain = temp[0]
	}

	// Check for an empty or missing domain; used with local user accounts
	if domain == "" {
		domain = "."
	}

	// Convert username to LPCWSTR
	pUser, err := syscall.UTF16PtrFromString(user)
	if err != nil {
		err = fmt.Errorf("there was an error converting the username \"%s\" to LPCWSTR: %s", user, err)
		return
	}

	// Convert the domain to LPCWSTR
	pDomain, err := syscall.UTF16PtrFromString(domain)
	if err != nil {
		err = fmt.Errorf("there was an error converting the domain \"%s\" to LPCWSTR: %s", domain, err)
		return
	}

	// Convert the password to LPCWSTR
	pPassword, err := syscall.UTF16PtrFromString(password)
	if err != nil {
		err = fmt.Errorf("there was an error converting the password \"%s\" to LPCWSTR: %s", password, err)
		return
	}

	return advapi32.LogonUser(pUser, pDomain, pPassword, logonType, logonProvider)
}

// MakeTokenN creates a NEW CREDENTIALS logon, type 9, and applies it to the current process using the
// ImpersonateLoggedOnUser Windows API call
// The "N" in the function name is for Native as it avoids using external packages
func MakeTokenN(user string, password string, domain string) (err error) {
	hToken, err := LogonUserN(user, password, domain, advapi32.LOGON32_LOGON_NEW_CREDENTIALS, advapi32.LOGON32_PROVIDER_DEFAULT)
	if err != nil {
		err = fmt.Errorf("there was an error calling LogonUserN: %s", err)
		return
	}

	err = advapi32.ImpersonateLoggedOnUserN(hToken)
	if err != nil {
		err = fmt.Errorf("there was an error calling ImpersonateLoggedOnUser: %s", err)
	}
	return
}

// OpenProcessTokenG opens the access token associated with a process
// The "G" at the end of the function name is for Golang because it uses the golang.org/x/sys/windows Go package
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
func OpenProcessTokenG(handle windows.Handle) (token windows.Token, err error) {
	// BOOL OpenProcessToken(
	//  [in]  HANDLE  ProcessHandle,
	//  [in]  DWORD   DesiredAccess,
	//  [out] PHANDLE TokenHandle
	//);
	// These token privs are required to call CreateProcessWithToken later
	err = windows.OpenProcessToken(handle, windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_QUERY, &token)
	if err != nil {
		err = fmt.Errorf("there was an error calling windows.OpenProcessToken: %s", err)
	}
	err = nil
	return
}

// PrivilegeAttributeToString converts a privilege attribute integer to a string
func PrivilegeAttributeToString(attribute uint32) string {
	// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges
	switch attribute {
	case 0x00000000:
		return ""
	case 0x00000001:
		return "SE_PRIVILEGE_ENABLED_BY_DEFAULT"
	case 0x00000002:
		return "SE_PRIVILEGE_ENABLED"
	case 0x00000001 | 0x00000002:
		return "SE_PRIVILEGE_ENABLED_BY_DEFAULT,SE_PRIVILEGE_ENABLED"
	case 0x00000004:
		return "SE_PRIVILEGE_REMOVED"
	case 0x80000000:
		return "SE_PRIVILEGE_USED_FOR_ACCESS"
	case 0x00000001 | 0x00000002 | 0x00000004 | 0x80000000:
		return "SE_PRIVILEGE_VALID_ATTRIBUTES"
	default:
		return fmt.Sprintf("Unknown SE_PRIVILEGE_ value: 0x%X", attribute)
	}
}

// StealTokenG opens the provided input process, duplicates its access token, and returns it
// The "G" at the end of the function name is for Golang because it uses the golang.org/x/sys/windows Go package
func StealTokenG(pid uint32) (hToken windows.Token, err error) {
	// Get handle to target process
	// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
	// HANDLE OpenProcess(
	//  [in] DWORD dwDesiredAccess,
	//  [in] BOOL  bInheritHandle,
	//  [in] DWORD dwProcessId
	//);
	var hProcess windows.Handle
	hProcess, err = windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, true, pid)
	if err != nil {
		err = fmt.Errorf("there was an error calling OpenProcess: %s", err)
		return
	}

	// Close the handle when done
	defer func(handle windows.Handle) {
		err := windows.CloseHandle(handle)
		if err != nil {

		}
	}(hProcess)

	// Get process token
	// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
	// BOOL OpenProcessToken(
	//  [in]  HANDLE  ProcessHandle,
	//  [in]  DWORD   DesiredAccess,
	//  [out] PHANDLE TokenHandle
	//);
	// These token privs are required to call CreateProcessWithToken later
	err = windows.OpenProcessToken(hProcess, windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_QUERY, &hToken)
	if err != nil {
		err = fmt.Errorf("there was an error calling OpenProcessToken: %s", err)
	}
	err = nil
	return
}

// SetThreadTokenG assigns or removes an impersonation token
// The "G" at the end of the function name is for Golang because it uses the golang.org/x/sys/windows Go package
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadtoken
func SetThreadTokenG(hThread uintptr, hToken windows.Token) (err error) {
	var dup windows.Token
	var attr windows.SecurityAttributes
	err = windows.DuplicateTokenEx(
		hToken,
		windows.TOKEN_ALL_ACCESS,
		&attr,
		windows.SecurityDelegation,
		windows.TokenPrimary,
		&dup,
	)
	if err != nil {
		return
	}

	err = windows.SetThreadToken(nil, dup)
	if err != nil {
		err = fmt.Errorf("there was an error calling windows.SetThreadToken: %s\n", err)
		return
	}
	return

	advapi32.SetThreadToken(unsafe.Pointer(uintptr(0)), unsafe.Pointer(&dup))
	return
}

// StringToCharPtr converts a Go string to the LPCSTR data type
//https://medium.com/@justen.walker/breaking-all-the-rules-using-go-to-call-windows-api-2cbfd8c79724
func StringToCharPtr(str string) uintptr {
	return uintptr(unsafe.Pointer(&append([]byte(str), 0)[0]))
}

// tokenTypeToString converts a TOKEN_TYPE uint32 value to it's associated string
func tokenTypeToString(tokenType uint32) string {
	switch tokenType {
	case advapi32.TokenPrimary:
		return "Primary"
	case advapi32.TokenImpersonation:
		return "Impersonation"
	default:
		return fmt.Sprintf("unknown TOKEN_TYPE: %d", tokenType)
	}
}

// WhoamiG enumerates information about both the process and thread token currently being used
// The "G" at the end of the function name is for Golang because it uses the golang.org/x/sys/windows Go package
func WhoamiG() (whoami string, err error) {
	// Process
	tProc := windows.GetCurrentProcessToken()

	// Thread
	tThread := windows.GetCurrentThreadEffectiveToken()

	// Get Process Token TOKEN_STATISTICS structure
	statProc, err := GetTokenStatsG(tProc)
	if err != nil {
		return
	}
	whoami += fmt.Sprintf("Process (%s) Token:\n", tokenTypeToString(statProc.TokenType))
	whoami += fmt.Sprintf("\tToken ID: 0x%X", statProc.TokenId.LowPart)
	whoami += fmt.Sprintf(",Logon ID: 0x%X", statProc.AuthenticationId.LowPart)
	whoami += fmt.Sprintf(",Privilege Count: %d", statProc.PrivilegeCount)
	whoami += fmt.Sprintf(",Group Count: %d", statProc.GroupCount)
	whoami += fmt.Sprintf(",Type: %s", tokenTypeToString(statProc.TokenType))
	whoami += fmt.Sprintf(",Impersonation Level: %s", impersonationToString(statProc.ImpersonationLevel))

	statThread, err := GetTokenStatsG(tThread)
	if err != nil {
		return
	}

	whoami += fmt.Sprintf("\nThread (%s) Token:\n", tokenTypeToString(statThread.TokenType))
	whoami += fmt.Sprintf("\tToken ID: 0x%X", statThread.TokenId.LowPart)
	whoami += fmt.Sprintf(",Logon ID: 0x%X", statThread.AuthenticationId.LowPart)
	whoami += fmt.Sprintf(",Privilege Count: %d", statThread.PrivilegeCount)
	whoami += fmt.Sprintf(",Group Count: %d", statThread.GroupCount)
	whoami += fmt.Sprintf(",Type: %s", tokenTypeToString(statThread.TokenType))
	whoami += fmt.Sprintf(",Impersonation Level: %s", impersonationToString(statThread.ImpersonationLevel))

	return
}

// WhoamiN enumerates information about both the process and thread token currently being used
// The "N" in the function name is for Native as it avoids using external packages
func WhoamiN() (whoami string, err error) {
	// Process
	tProc := process.GetCurrentProcessTokenN()

	// Thread
	tThread := process.GetCurrentThreadEffectiveTokenN()

	// Get Process Token TOKEN_STATISTICS structure
	statProc, err := GetTokenStatsN(tProc)
	if err != nil {
		return
	}
	whoami += fmt.Sprintf("Process (%s) Token:\n", tokenTypeToString(statProc.TokenType))
	whoami += fmt.Sprintf("\tToken ID: 0x%X", statProc.TokenId.LowPart)
	whoami += fmt.Sprintf(",Logon ID: 0x%X", statProc.AuthenticationId.LowPart)
	whoami += fmt.Sprintf(",Privilege Count: %d", statProc.PrivilegeCount)
	whoami += fmt.Sprintf(",Group Count: %d", statProc.GroupCount)
	whoami += fmt.Sprintf(",Type: %s", tokenTypeToString(statProc.TokenType))
	whoami += fmt.Sprintf(",Impersonation Level: %s", impersonationToString(statProc.ImpersonationLevel))

	statThread, err := GetTokenStatsN(tThread)
	if err != nil {
		return
	}

	whoami += fmt.Sprintf("\nThread (%s) Token:\n", tokenTypeToString(statThread.TokenType))
	whoami += fmt.Sprintf("\tToken ID: 0x%X", statThread.TokenId.LowPart)
	whoami += fmt.Sprintf(",Logon ID: 0x%X", statThread.AuthenticationId.LowPart)
	whoami += fmt.Sprintf(",Privilege Count: %d", statThread.PrivilegeCount)
	whoami += fmt.Sprintf(",Group Count: %d", statThread.GroupCount)
	whoami += fmt.Sprintf(",Type: %s", tokenTypeToString(statThread.TokenType))
	whoami += fmt.Sprintf(",Impersonation Level: %s", impersonationToString(statThread.ImpersonationLevel))

	return
}
