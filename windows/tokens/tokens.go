// +build windows

package tokens

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/windows"
	"oddments/windows/process"
	"strings"
	"syscall"
	"unsafe"
)

// LOGON32_LOGON_ constants from winbase.h
// The type of logon operation to perform
const (
	LOGON32_LOGON_INTERACTIVE       uint32 = 2
	LOGON32_LOGON_NETWORK           uint32 = 3
	LOGON32_LOGON_BATCH             uint32 = 4
	LOGON32_LOGON_SERVICE           uint32 = 5
	LOGON32_LOGON_UNLOCK            uint32 = 7
	LOGON32_LOGON_NETWORK_CLEARTEXT uint32 = 8
	LOGON32_LOGON_NEW_CREDENTIALS   uint32 = 9
)

// LOGON32_PROVIDER_ constants
// The logon provider
const (
	LOGON32_PROVIDER_DEFAULT uint32 = iota
	LOGON32_PROVIDER_WINNT35
	LOGON32_PROVIDER_WINNT40
	LOGON32_PROVIDER_WINNT50
	LOGON32_PROVIDER_VIRTUAL
)

// SECURITY_IMPERSONATION_LEVEL enumeration
// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-security_impersonation_level
const (
	SecurityAnonymous uint32 = iota
	SecurityIdentification
	SecurityImpersonation
	SecurityDelegation
)

// SECURITY_IMPERSONATION_LEVEL enumeration contains values that specify security impersonation levels
// Security impersonation levels govern the degree to which a server process can act on behalf of a client process.
// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-security_impersonation_level
// typedef enum _SECURITY_IMPERSONATION_LEVEL {
//  SecurityAnonymous,
//  SecurityIdentification,
//  SecurityImpersonation,
//  SecurityDelegation
//} SECURITY_IMPERSONATION_LEVEL, *PSECURITY_IMPERSONATION_LEVEL;
const (
	SE_PRIVILEGE_USED_FOR_ACCESS uint32 = iota
	SE_PRIVILEGE_ENABLED_BY_DEFAULT
	SE_PRIVILEGE_ENABLED
	_
	SE_PRIVILEGE_REMOVED
)

// SE_ Privilege Constants (Authorization)
// https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
const (
	SE_CREATE_TOKEN_NAME           string = "SeCreateTokenPrivilege"
	SE_ASSIGNPRIMARYTOKEN_NAME     string = "SeAssignPrimaryTokenPrivilege"
	SE_LOCK_MEMORY_NAME            string = "SeLockMemoryPrivilege"
	SE_INCREASE_QUOTA_NAME         string = "SeIncreaseQuotaPrivilege"
	SE_UNSOLICITED_INPUT_NAME      string = "SeUnsolicitedInputPrivilege"
	SE_MACHINE_ACCOUNT_NAME        string = "SeMachineAccountPrivilege"
	SE_TCB_NAME                    string = "SeTcbPrivilege"
	SE_SECURITY_NAME               string = "SeSecurityPrivilege"
	SE_TAKE_OWNERSHIP_NAME         string = "SeTakeOwnershipPrivilege"
	SE_LOAD_DRIVER_NAME            string = "SeLoadDriverPrivilege"
	SE_SYSTEM_PROFILE_NAME         string = "SeSystemProfilePrivilege"
	SE_SYSTEMTIME_NAME             string = "SeSystemtimePrivilege"
	SE_PROF_SINGLE_PROCESS_NAME    string = "SeProfileSingleProcessPrivilege"
	SE_INC_BASE_PRIORITY_NAME      string = "SeIncreaseBasePriorityPrivilege"
	SE_CREATE_PAGEFILE_NAME        string = "SeCreatePagefilePrivilege"
	SE_CREATE_PERMANENT_NAME       string = "SeCreatePermanentPrivilege"
	SE_BACKUP_NAME                 string = "SeBackupPrivilege"
	SE_RESTORE_NAME                string = "SeRestorePrivilege"
	SE_SHUTDOWN_NAME               string = "SeShutdownPrivilege"
	SE_DEBUG_NAME                  string = "SeDebugPrivilege"
	SE_AUDIT_NAME                  string = "SeAuditPrivilege"
	SE_SYSTEM_ENVIRONMENT_NAME     string = "SeSystemEnvironmentPrivilege"
	SE_CHANGE_NOTIFY_NAME          string = "SeChangeNotifyPrivilege"
	SE_REMOTE_SHUTDOWN_NAME        string = "SeRemoteShutdownPrivilege"
	SE_UNDOCK_NAME                 string = "SeUndockPrivilege"
	SE_SYNC_AGENT_NAME             string = "SeSyncAgentPrivilege"
	SE_ENABLE_DELEGATION_NAME      string = "SeEnableDelegationPrivilege"
	SE_MANAGE_VOLUME_NAME          string = "SeManageVolumePrivilege"
	SE_IMPERSONATE_NAME            string = "SeImpersonatePrivilege"
	SE_CREATE_GLOBAL_NAME          string = "SeCreateGlobalPrivilege"
	SE_TRUSTED_CREDMAN_ACCESS_NAME string = "SeTrustedCredManAccessPrivilege"
	SE_RELABEL_NAME                string = "SeRelabelPrivilege"
	SE_INC_WORKING_SET_NAME        string = "SeIncreaseWorkingSetPrivilege"
	SE_TIME_ZONE_NAME              string = "SeTimeZonePrivilege"
	SE_CREATE_SYMBOLIC_LINK_NAME   string = "SeCreateSymbolicLinkPrivilege"
)

// EXTENDED_NAME_FORMAT
// https://docs.microsoft.com/en-us/windows/win32/api/secext/ne-secext-extended_name_format
const (
	NameUnknown uint32 = iota
	NameFullyQualifiedDN
	NameSamCompatible
	NameDisplay
	NameUniqueId
	NameCanonical
	NameUserPrincipal
	NameCanonicalEx
	NameServicePrincipal
	NameDnsDomain
	NameGivenName
	NameSurname
)

// TOKEN_ Access Rights for Access-Token Objects
// https://docs.microsoft.com/en-us/windows/win32/secauthz/access-rights-for-access-token-objects
// https://referencesource.microsoft.com/#System.Workflow.Runtime/DebugEngine/NativeMethods.cs,ba613dc523f12d3e,references
const (
	STANDARD_RIGHTS_REQUIRED int = 0x000F0000
	TOKEN_ASSIGN_PRIMARY     int = 0x0001
	TOKEN_DUPLICATE          int = 0x0002
	TOKEN_IMPERSONATE        int = 0x0004
	TOKEN_QUERY              int = 0x0008
	TOKEN_QUERY_SOURCE       int = 0x0010
	TOKEN_ADJUST_PRIVILEGES  int = 0x0020
	TOKEN_ADJUST_GROUPS      int = 0x0040
	TOKEN_ADJUST_DEFAULT     int = 0x0080
	TOKEN_ADJUST_SESSIONID   int = 0x0100
	TOKEN_ALL_ACCESS         int = STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT
)

// TOKEN_INFORMATION_CLASS enumeration contains values that specify the type of information being assigned to or retrieved from an access token.
// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class
const (
	TokenUser uint32 = iota + 1
	TokenGroups
	TokenPrivileges
	TokenOwner
	TokenPrimaryGroup
	TokenDefaultDacl
	TokenSource
	TokenType
	TokenImpersonationLevel
	TokenStatistics
	TokenRestrictedSids
	TokenSessionId
	TokenGroupsAndPrivileges
	TokenSessionReference
	TokenSandBoxInert
	TokenAuditPolicy
	TokenOrigin
	TokenElevationType
	TokenLinkedToken
	TokenElevation
	TokenHasRestrictions
	TokenAccessInformation
	TokenVirtualizationAllowed
	TokenVirtualizationEnabled
	TokenIntegrityLevel
	TokenUIAccess
	TokenMandatoryPolicy
	TokenLogonSid
	TokenIsAppContainer
	TokenCapabilities
	TokenAppContainerSid
	TokenAppContainerNumber
	TokenUserClaimAttributes
	TokenDeviceClaimAttributes
	TokenRestrictedUserClaimAttributes
	TokenRestrictedDeviceClaimAttributes
	TokenDeviceGroups
	TokenRestrictedDeviceGroups
	TokenSecurityAttributes
	TokenIsRestricted
	TokenProcessTrustLevel
	TokenPrivateNameSpace
	TokenSingletonAttributes
	TokenBnoIsolation
	TokenChildProcessFlags
	TokenIsLessPrivilegedAppContainer
	TokenIsSandboxed
	MaxTokenInfoClass
)

// StealToken opens the provided input process, duplicates its access token, and returns it
func StealToken(pid uint32) (hToken windows.Token, err error) {
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

// MakeToken creates a NEW CREDENTIALS logon, type 9, and applies it to the current process using the
// ImpersonateLoggedOnUser Windows API call
func MakeToken(user string, password string, domain string) (err error) {
	hToken, err := LogonUserN(user, password, domain, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT)
	if err != nil {
		err = fmt.Errorf("there was an error calling LogonUserN: %s", err)
		return
	}

	err = ImpersonateLoggedOnUserN(hToken)
	if err != nil {
		err = fmt.Errorf("there was an error calling ImpersonateLoggedOnUser: %s", err)
	}
	return
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

	// The LogonUser function was not available in the golang.org/x/sys/windows package at the time of writing
	Advapi32 := windows.NewLazySystemDLL("Advapi32.dll")
	LogonUserW := Advapi32.NewProc("LogonUserW")

	// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw
	// BOOL LogonUserW(
	//  [in]           LPCWSTR lpszUsername,
	//  [in, optional] LPCWSTR lpszDomain,
	//  [in, optional] LPCWSTR lpszPassword,
	//  [in]           DWORD   dwLogonType,
	//  [in]           DWORD   dwLogonProvider,
	//  [out]          PHANDLE phToken
	//);

	_, _, err = LogonUserW.Call(
		uintptr(unsafe.Pointer(pUser)),
		uintptr(unsafe.Pointer(pDomain)),
		uintptr(unsafe.Pointer(pPassword)),
		uintptr(logonType),
		uintptr(logonProvider),
		uintptr(unsafe.Pointer(&hToken)),
	)
	if err != syscall.Errno(0) {
		err = fmt.Errorf("there was an error calling LogonUserA: %s", err)
		return
	}

	err = nil
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

	Advapi32 := windows.NewLazySystemDLL("Advapi32.dll")
	LogonUserW := Advapi32.NewProc("LogonUserW")

	// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw
	// BOOL LogonUserW(
	//  [in]           LPCWSTR lpszUsername,
	//  [in, optional] LPCWSTR lpszDomain,
	//  [in, optional] LPCWSTR lpszPassword,
	//  [in]           DWORD   dwLogonType,
	//  [in]           DWORD   dwLogonProvider,
	//  [out]          PHANDLE phToken
	//);

	var phToken unsafe.Pointer
	_, _, err = LogonUserW.Call(
		uintptr(unsafe.Pointer(pUser)),
		uintptr(unsafe.Pointer(pDomain)),
		uintptr(unsafe.Pointer(pPassword)),
		uintptr(logonType),
		uintptr(logonProvider),
		uintptr(unsafe.Pointer(&phToken)),
	)
	if err != syscall.Errno(0) {
		err = fmt.Errorf("there was an error calling LogonUserA: %s", err)
		return
	}

	err = nil
	hToken = &phToken
	return
}

// SetThreadToken assigns or removes an impersonation token
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadtoken
func SetThreadToken(hThread uintptr, hToken windows.Token) (err error) {
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

	Advapi32 := windows.NewLazySystemDLL("Advapi32.dll")
	SetThreadToken := Advapi32.NewProc("SetThreadToken")

	// BOOL SetThreadToken(
	//  [in, optional] PHANDLE Thread,
	//  [in, optional] HANDLE  Token
	//);
	_, _, err = SetThreadToken.Call(0, uintptr(unsafe.Pointer(&dup)))
	if err != syscall.Errno(0) {
		err = fmt.Errorf("there was an error calling SetThreadToken: %s", err)
		return
	}
	err = nil
	return
}

// StringToCharPtr converts a Go string to the LPCSTR data type
//https://medium.com/@justen.walker/breaking-all-the-rules-using-go-to-call-windows-api-2cbfd8c79724
func StringToCharPtr(str string) uintptr {
	return uintptr(unsafe.Pointer(&append([]byte(str), 0)[0]))
}

// DuplicateToken
// https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetoken
func DuplicateToken(hToken windows.Token) (token windows.Token, err error) {
	Advapi32 := windows.NewLazySystemDLL("Advapi32.dll")
	DuplicateToken := Advapi32.NewProc("DuplicateToken")

	//BOOL DuplicateToken(
	//  [in]  HANDLE                       ExistingTokenHandle,
	//  [in]  SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
	//  [out] PHANDLE                      DuplicateTokenHandle
	//);

	_, _, err = DuplicateToken.Call(uintptr(unsafe.Pointer(&hToken)), uintptr(SecurityDelegation), uintptr(unsafe.Pointer(&token)))
	if err != syscall.Errno(0) {
		err = fmt.Errorf("there was an error calling DuplicateToken: %s", err)
		return
	}
	err = nil
	return
}

// ImpersonateLoggedOnUserG lets the calling thread impersonate the security context of a logged-on user.
// The user is represented by a token handle.
// The "G" at the end of the function name is for Golang because it uses the golang.org/x/sys/windows Go package
// https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-impersonateloggedonuser
func ImpersonateLoggedOnUserG(hToken windows.Token) (err error) {
	Advapi32 := windows.NewLazySystemDLL("Advapi32.dll")
	ImpersonateLoggedOnUser := Advapi32.NewProc("ImpersonateLoggedOnUser")

	// BOOL ImpersonateLoggedOnUser(
	//  [in] HANDLE hToken
	//);
	_, _, err = ImpersonateLoggedOnUser.Call(uintptr(hToken))
	if err != syscall.Errno(0) {
		err = fmt.Errorf("there was an error calling ImpersonateLoggedOnUser: %s", err)
		return
	}
	err = nil
	return
}

// ImpersonateLoggedOnUserN lets the calling thread impersonate the security context of a logged-on user.
// The user is represented by a token handle.
// The "N" in the function name is for Native as it avoids using external packages
// https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-impersonateloggedonuser
func ImpersonateLoggedOnUserN(hToken *unsafe.Pointer) (err error) {
	Advapi32 := windows.NewLazySystemDLL("Advapi32.dll")
	ImpersonateLoggedOnUser := Advapi32.NewProc("ImpersonateLoggedOnUser")

	// BOOL ImpersonateLoggedOnUser(
	//  [in] HANDLE hToken
	//);
	_, _, err = ImpersonateLoggedOnUser.Call(uintptr(*hToken))
	if err != syscall.Errno(0) {
		err = fmt.Errorf("there was an error calling ImpersonateLoggedOnUser: %s", err)
		return
	}
	err = nil
	return
}

// PrivilegeCheckN determines whether a specified set of privileges are enabled in an access token
// The "N" in the function name is for Native as it avoids using external packages
// https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-privilegecheck
func PrivilegeCheckN(hToken *unsafe.Pointer, privs PRIVILEGE_SET) (hasPriv bool, err error) {
	Advapi32 := windows.NewLazySystemDLL("Advapi32.dll")
	PrivilegeCheck := Advapi32.NewProc("PrivilegeCheck")
	// BOOL PrivilegeCheck(
	//  [in]      HANDLE         ClientToken,
	//  [in, out] PPRIVILEGE_SET RequiredPrivileges,
	//  [out]     LPBOOL         pfResult
	//);

	ret, _, err := PrivilegeCheck.Call(uintptr(*hToken), uintptr(unsafe.Pointer(&privs)), uintptr(unsafe.Pointer(&hasPriv)))
	if err != syscall.Errno(0) || ret == 0 {
		err = fmt.Errorf("there was an error calling PrivilegeCheck: %s", err)
		return
	}
	err = nil
	fmt.Printf("[++++++++++] Privs: %+v\n", privs)
	fmt.Printf("[++++++++++] Has: %v\n", hasPriv)
	return
}

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

// AdjustTokenPrivilegesN enables or disables privileges in the specified access token.
// Enabling or disabling privileges in an access token requires TOKEN_ADJUST_PRIVILEGES access.
// The "N" in the function name is for Native as it avoids using external packages
// https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
func AdjustTokenPrivilegesN(hToken windows.Token, disable bool, priv string) (err error) {
	Advapi32 := windows.NewLazySystemDLL("Advapi32.dll")
	AdjustTokenPrivileges := Advapi32.NewProc("AdjustTokenPrivileges")

	privileges := [1]LUID_AND_ATTRIBUTES{
		{Attributes: SE_PRIVILEGE_ENABLED},
	}

	if disable {
		privileges[0].Attributes = SE_PRIVILEGE_REMOVED
	}

	privileges[0].Luid, err = LookupPrivilegeValueN(priv)
	if err != nil {
		return
	}

	NewState := TOKEN_PRIVILEGES{
		PrivilegeCount: uint32(len(privileges)),
		Privileges:     privileges,
	}

	// BOOL AdjustTokenPrivileges(
	//  [in]            HANDLE            TokenHandle,
	//  [in]            BOOL              DisableAllPrivileges,
	//  [in, optional]  PTOKEN_PRIVILEGES NewState,
	//  [in]            DWORD             BufferLength,
	//  [out, optional] PTOKEN_PRIVILEGES PreviousState,
	//  [out, optional] PDWORD            ReturnLength
	//);
	ret, _, err := AdjustTokenPrivileges.Call(
		uintptr(unsafe.Pointer(&hToken)),
		0,
		uintptr(unsafe.Pointer(&NewState)),
		0,
		0,
		0,
	)

	if ret == 0 {
		err = fmt.Errorf("there was an error calling AdjustTokenPrivileges: %s", err)
		return
	}
	err = nil
	return
}

// LookupPrivilegeValueN retrieves the locally unique identifier (LUID) used on a specified system to locally represent
// the specified privilege name
// The "N" in the function name is for Native as it avoids using external packages
// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluew
func LookupPrivilegeValueN(priv string) (lpLuid LUID, err error) {
	if priv == "" {
		err = fmt.Errorf("A privilege string (e.g., SeDebugPrivilege) is required to call the LookupPrivilegeValue function")
		return
	}

	lpName, err := syscall.UTF16PtrFromString(priv)
	if err != nil {
		err = fmt.Errorf("there was an error converting the privilege \"%s\" to LPCWSTR: %s", priv, err)
		return
	}

	Advapi32 := windows.NewLazySystemDLL("Advapi32.dll")
	LookupPrivilegeValueW := Advapi32.NewProc("LookupPrivilegeValueW")

	// BOOL LookupPrivilegeValueW(
	//  [in, optional] LPCWSTR lpSystemName,
	//  [in]           LPCWSTR lpName,
	//  [out]          PLUID   lpLuid
	//);

	_, _, err = LookupPrivilegeValueW.Call(0, uintptr(unsafe.Pointer(lpName)), uintptr(unsafe.Pointer(&lpLuid)))
	if err != syscall.Errno(0) {
		err = fmt.Errorf("there was an error calling LookupPrivilegeValueW for privilege \"%s\": %s", priv, err)
		return
	}
	err = nil
	return
}

// EnablePrivilege is a meta function that enables the provided privilege for the current process
func EnablePrivilege(privilege string) (err error) {
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

// WhoamiG enumerates information about both the process and thread token currently being used
// The "G" at the end of the function name is for Golang because it uses the golang.org/x/sys/windows Go package
func WhoamiG() (whoami string, err error) {
	// Process
	/*
		hProc := windows.CurrentProcess()
		var tProc windows.Token
		err = windows.OpenProcessToken(hProc, windows.TOKEN_QUERY, &tProc)
		if err != nil {
			err = fmt.Errorf("there was an error calling windows.OpenProcessToken: %s", err)
			return
		}
	*/

	tProc := windows.GetCurrentProcessToken()

	// Thread
	// You do not need to close the pseudo-handle when you no longer need it
	/*
		hThread := windows.CurrentThread()
		var tThread windows.Token
		err = windows.OpenThreadToken(hThread, windows.TOKEN_QUERY, true, &tThread)
		if err != nil {
			err = fmt.Errorf("there was an error calling windows.OpenThreadToken: %s", err)
			return
		}
	*/
	// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthreadeffectivetoken
	tThread := windows.GetCurrentThreadEffectiveToken()

	// Get Process Token TOKEN_STATISTICS structure
	statProc, err := GetTokenStats(tProc)
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

	statThread, err := GetTokenStats(tThread)
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
	/*
		hProc, err := process.GetCurrentProcessN()
		if err != nil{return}

		defer func(){
			err := CloseHandleN(hProc)
			if err != nil {
				log.Fatal(err)
			}
		}()

		tProc, err := OpenProcessTokenN(hProc,TOKEN_QUERY)
		if err != nil {
			err = fmt.Errorf("there was an error calling windows.OpenProcessToken: %s", err)
			return
		}
	*/
	tProc := process.GetCurrentProcessTokenN()

	// Thread
	/*
		hThread, err := process.GetCurrentThreadN()
		if err != nil{return "", err}

		defer func(){
			err := CloseHandleN(hThread)
			if err != nil {
				log.Fatal(err)
			}
		}()

		tThread, err := OpenThreadTokenN(hThread, uint32(TOKEN_QUERY), true)
		if err != nil{return "",err}
	*/
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

// OpenThreadTokenN opens the access token associated with a thread.
// The "N" in the function name is for Native as it avoids using external packages
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken
func OpenThreadTokenN(ThreadHandle *unsafe.Pointer, DesiredAccess uint32, OpenAsSelf bool) (hToken *unsafe.Pointer, err error) {
	Advapi32 := windows.NewLazySystemDLL("Advapi32.dll")
	OpenThreadToken := Advapi32.NewProc("OpenThreadToken")

	// BOOL OpenThreadToken(
	//  [in]  HANDLE  ThreadHandle,
	//  [in]  DWORD   DesiredAccess,
	//  [in]  BOOL    OpenAsSelf,
	//  [out] PHANDLE TokenHandle
	//);

	var self uintptr
	if OpenAsSelf {
		self = 1
	}
	var TokenHandle unsafe.Pointer

	ret, _, err := OpenThreadToken.Call(uintptr(*ThreadHandle), uintptr(DesiredAccess), self, uintptr(unsafe.Pointer(&TokenHandle)))
	if err != syscall.Errno(0) || ret == 0 {
		err = fmt.Errorf("there was an error calling Advapi32!OpenThreadToken with return code 0: %s", err)
		return
	}
	return &TokenHandle, nil
}

// GetTokenStats uses the GetTokenInformation Windows API call to gather information about the provided access token
// by retrieving the token's associated TOKEN_STATISTICS structure
// https://github.com/gentilkiwi/mimikatz/blob/e10bde5b16b747dc09ca5146f93f2beaf74dd17a/mimikatz/modules/kuhl_m_token.c#L181
func GetTokenStats(token windows.Token) (tokenStats TOKEN_STATISTICS, err error) {
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
func GetTokenStatsN(token *unsafe.Pointer) (tokenStats TOKEN_STATISTICS, err error) {
	var TokenStatistics uint32 = 10
	info, _, err := GetTokenInformationN(token, TokenStatistics)
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

// GetTokenInformationN
// The caller is responsible for marshalling the bytes into the appropriate structure
// The "N" in the function name is for Native as it avoids using external packages
// https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation
func GetTokenInformationN(TokenHandle *unsafe.Pointer, TokenInformationClass uint32) (TokenInformation *bytes.Buffer, ReturnLength uint32, err error) {
	Advapi32 := windows.NewLazySystemDLL("Advapi32.dll")
	GetTokenInformation := Advapi32.NewProc("GetTokenInformation")

	// BOOL GetTokenInformation(
	//  [in]            HANDLE                  TokenHandle,
	//  [in]            TOKEN_INFORMATION_CLASS TokenInformationClass,
	//  [out, optional] LPVOID                  TokenInformation,
	//  [in]            DWORD                   TokenInformationLength,
	//  [out]           PDWORD                  ReturnLength
	//);

	// Call the function without the TokenInformation parameter to determine the required buffer length for the TokenInformation structure
	ret, _, err := GetTokenInformation.Call(uintptr(*TokenHandle), uintptr(TokenInformationClass), 0, 0, uintptr(unsafe.Pointer(&ReturnLength)))
	if err != syscall.ERROR_INSUFFICIENT_BUFFER {
		err = fmt.Errorf("there was an error calling Advapi32!GetTokenInformation with return code %d: %d, %s", ret, err, err)
		return
	}

	// Make the call with the known size of the object
	info := bytes.NewBuffer(make([]byte, ReturnLength))
	ret, _, err = GetTokenInformation.Call(
		uintptr(*TokenHandle),
		uintptr(TokenInformationClass),
		uintptr(unsafe.Pointer(&info.Bytes()[0])),
		uintptr(ReturnLength),
		uintptr(unsafe.Pointer(&ReturnLength)),
	)
	if err != syscall.Errno(0) || ret == 0 {
		err = fmt.Errorf("there was an error calling Advapi32!GetTokenInformation with return code %d: %s", ret, err)
		return
	}
	return info, ReturnLength, nil
}

// RevertToSelfN terminates the impersonation of a client application
// https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself
func RevertToSelfN() (err error) {
	Advapi32 := windows.NewLazySystemDLL("Advapi32.dll")
	RevertToSelf := Advapi32.NewProc("RevertToSelf")

	ret, _, err := RevertToSelf.Call()
	if err != syscall.Errno(0) || ret == 0 {
		err = fmt.Errorf("there was an error calling Advapi32!RevertToSelf with return code %d: %s", ret, err)
		return
	}
	return nil
}

// impersonationToString converts a SECURITY_IMPERSONATION_LEVEL uint32 value to it's associated string
func impersonationToString(level uint32) string {
	switch level {
	case SecurityAnonymous:
		return "Anonymous"
	case SecurityIdentification:
		return "Identification"
	case SecurityImpersonation:
		return "Impersonation"
	case SecurityDelegation:
		return "Delegation"
	default:
		return fmt.Sprintf("unknown SECURITY_IMPERSONATION_LEVEL: %d", level)
	}
}

// tokenTypeToString converts a TOKEN_TYPE uint32 value to it's associated string
func tokenTypeToString(tokenType uint32) string {
	switch tokenType {
	case TokenPrimary:
		return "Primary"
	case TokenImpersonation:
		return "Impersonation"
	default:
		return fmt.Sprintf("unknown TOKEN_TYPE: %d", tokenType)
	}
}

// CloseHandleN closes an open object handle
// The "N" in the function name is for Native as it avoids using external packages
// https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
func CloseHandleN(handle *unsafe.Pointer) (err error) {
	Kernel32 := windows.NewLazySystemDLL("Kernel32.dll")
	CloseHandle := Kernel32.NewProc("CloseHandle")

	// BOOL CloseHandle(
	//  [in] HANDLE hObject
	//);

	ret, _, err := CloseHandle.Call(uintptr(*handle))
	if err != syscall.Errno(0) || ret == 0 {
		err = fmt.Errorf("there was an error calling Advapi32!CloseHandle with return code %d: %s", ret, err)
		return
	}
	return nil
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

// OpenProcessTokenN opens the access token associated with a process
// The "N" in the function name is for Native as it avoids using external packages
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
func OpenProcessTokenN(ProcessHandle *unsafe.Pointer, DesiredAccess int) (token *unsafe.Pointer, err error) {
	Advapi32 := windows.NewLazySystemDLL("Advapi32.dll")
	OpenProcessToken := Advapi32.NewProc("OpenProcessToken")
	// BOOL OpenProcessToken(
	//  [in]  HANDLE  ProcessHandle,
	//  [in]  DWORD   DesiredAccess,
	//  [out] PHANDLE TokenHandle
	//);
	var TokenHandle unsafe.Pointer
	ret, _, err := OpenProcessToken.Call(uintptr(*ProcessHandle), uintptr(DesiredAccess), uintptr(unsafe.Pointer(&TokenHandle)))
	if err != syscall.Errno(0) || ret == 0 {
		err = fmt.Errorf("there was an error calling Advapi32!OpenProcessToken with return code %d: %s", ret, err)
		return
	}
	err = nil
	return &TokenHandle, nil
}

// LookupPrivilegeName retrieves the name that corresponds to the privilege represented on a specific system by a
// specified locally unique identifier (LUID).
// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegenamew
func LookupPrivilegeName(luid LUID) (privilege string, err error) {
	Advapi32 := windows.NewLazySystemDLL("Advapi32.dll")
	LookupPrivilegeNameW := Advapi32.NewProc("LookupPrivilegeNameW")

	// BOOL LookupPrivilegeNameW(
	//  [in, optional]  LPCWSTR lpSystemName,
	//  [in]            PLUID   lpLuid,
	//  [out, optional] LPWSTR  lpName,
	//  [in, out]       LPDWORD cchName
	//);

	// Call to determine the size
	var cchName uint32
	ret, _, err := LookupPrivilegeNameW.Call(0, uintptr(unsafe.Pointer(&luid)), 0, uintptr(unsafe.Pointer(&cchName)))
	if err.Error() != "The data area passed to a system call is too small." {
		return "", fmt.Errorf("there was an error calling advapi32!LookupPrivilegeName for %+v with return code %d: %s", luid, ret, err)
	}

	var lpName uint16
	ret, _, err = LookupPrivilegeNameW.Call(0, uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&lpName)), uintptr(unsafe.Pointer(&cchName)))
	if err != syscall.Errno(0) || ret == 0 {
		return "", fmt.Errorf("there was an error calling advapi32!LookupPrivilegeName with return code %d: %s", ret, err)
	}

	return windows.UTF16PtrToString(&lpName), nil
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

// CreateProcessWithTokenN creates a new process as the user associated with the passed in token
// This requires administrative privileges or at least the SE_IMPERSONATE_NAME privilege
func CreateProcessWithTokenN(token *unsafe.Pointer, application string, args string) (err error) {
	if application == "" {
		err = fmt.Errorf("a program must be provided for the CreateProcessWithToken call")
		return
	}

	// TODO Check that the calling process has the SE_IMPERSONATE_NAME privilege
	luid, err := LookupPrivilegeValueN("SeImpersonatePrivilege")
	if err != nil {
		return
	}

	l := LUID_AND_ATTRIBUTES{
		Luid:       luid,
		Attributes: SE_PRIVILEGE_ENABLED,
	}

	// Build the privilege set
	privs := PRIVILEGE_SET{
		PrivilegeCount: 1,
		Control:        0,
		Privilege:      []LUID_AND_ATTRIBUTES{l},
	}
	fmt.Printf("PRIVILEGE_SET: %+v", privs)
	hasPriv, err := PrivilegeCheckN(token, privs)

	// TODO try to enable the priv before returning with an error
	if !hasPriv {
		return fmt.Errorf("the provided access token does not have the SeImpersonatePrivilege and therefore can't be used to call CreateProcessWithToken")
	}

	Advapi32 := windows.NewLazySystemDLL("Advapi32.dll")
	CreateProcessWithToken := Advapi32.NewProc("CreateProcessWithTokenW")

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

	lpStartupInfo := &windows.StartupInfo{}
	lpProcessInformation := &windows.ProcessInformation{}

	fmt.Printf("[DEBUG] Calling CreateProcessWithToken(%v, %v, %s, %s)\n", token, process.LOGON_NETCREDENTIALS_ONLY, application, args)
	_, _, err = CreateProcessWithToken.Call(
		uintptr(unsafe.Pointer(&token)),
		uintptr(process.LOGON_NETCREDENTIALS_ONLY),
		uintptr(unsafe.Pointer(&lpApplicationName)),
		uintptr(unsafe.Pointer(&lpCommandLine)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(lpStartupInfo)),
		uintptr(unsafe.Pointer(lpProcessInformation)),
	)
	if err != syscall.Errno(0) {
		err = fmt.Errorf("there was an error calling CreateProcessWithToken: %s", err)
		return
	}

	err = nil
	return
}

// PRIVILEGE_SET specifies a set of privileges. It is also used to indicate which, if any, privileges are held by a
// user or group requesting access to an object.
// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-privilege_set
// typedef struct _PRIVILEGE_SET {
//  DWORD               PrivilegeCount;
//  DWORD               Control;
//  LUID_AND_ATTRIBUTES Privilege[ANYSIZE_ARRAY];
//} PRIVILEGE_SET, *PPRIVILEGE_SET;
type PRIVILEGE_SET struct {
	PrivilegeCount uint32 // Specifies the number of privileges in the privilege set.
	Control        uint32 // Indicates that all of the specified privileges must be held by the process requesting access. If this flag is not set, the presence of any privileges in the user's access token grants the access.
	Privilege      []LUID_AND_ATTRIBUTES
}

// LUID Describes a local identifier for an adapter
// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-luid
type LUID struct {
	LowPart  uint32
	HighPart int32
}

// LUID_AND_ATTRIBUTES structure represents a locally unique identifier (LUID) and its attributes
// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-luid_and_attributes
type LUID_AND_ATTRIBUTES struct {
	Luid       LUID
	Attributes uint32
}

// TOKEN_PRIVILEGES contains information about a set of privileges for an access token
// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges
type TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32
	Privileges     [1]LUID_AND_ATTRIBUTES
}

// TOKEN_STATISTICS contains information about an access token
// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_statistics
// typedef struct _TOKEN_STATISTICS {
//  LUID                         TokenId;
//  LUID                         AuthenticationId;
//  LARGE_INTEGER                ExpirationTime;
//  TOKEN_TYPE                   TokenType;
//  SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
//  DWORD                        DynamicCharged;
//  DWORD                        DynamicAvailable;
//  DWORD                        GroupCount;
//  DWORD                        PrivilegeCount;
//  LUID                         ModifiedId;
//} TOKEN_STATISTICS, *PTOKEN_STATISTICS;
type TOKEN_STATISTICS struct {
	TokenId            LUID
	AuthenticationId   LUID
	ExpirationTime     int64
	TokenType          uint32 // Enum of TokenPrimary 0 or TokenImpersonation 1
	ImpersonationLevel uint32 // Enum
	DynamicCharged     uint32
	DynamicAvailable   uint32
	GroupCount         uint32
	PrivilegeCount     uint32
	ModifiedId         LUID
}

// TOKEN_TYPE enumeration contains values that differentiate between a primary token and an impersonation token
// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_type
// typedef enum _TOKEN_TYPE {
//  TokenPrimary,
//  TokenImpersonation
//} TOKEN_TYPE;
const (
	TokenPrimary uint32 = iota + 1
	TokenImpersonation
)
