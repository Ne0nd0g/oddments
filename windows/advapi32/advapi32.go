package advapi32

import (
	// Standard
	"bytes"
	"fmt"
	"syscall"
	"unsafe"

	// X Packages
	"golang.org/x/sys/windows"
)

var Advapi32 = windows.NewLazySystemDLL("Advapi32.dll")

// Constants

// EXTENDED_NAME_FORMAT Specifies a format for a directory service object name.
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

// LOGON_ The logon option
const (
	LOGON_WITH_PROFILE        uint32 = 0x1
	LOGON_NETCREDENTIALS_ONLY uint32 = 0x2
)

// PRIVILEGE_SET structure specifies a set of privileges.
// It is also used to indicate which, if any, privileges are held by a user or group requesting access to an object.
// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-privilege_set
const (
	SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
	SE_PRIVILEGE_ENABLED            = 0x00000002
	SE_PRIVILEGE_REMOVED            = 0x00000003
	SE_PRIVILEGE_USED_FOR_ACCESS    = 0x80000000
)

// PROCESS_ Process Security and Access Rights
// https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
const (
	PROCESS_QUERY_INFORMATION uint32 = 0x0400
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

// SECURITY_IMPERSONATION_LEVEL enumeration contains values that specify security impersonation levels.
// Security impersonation levels govern the degree to which a server process can act on behalf of a client process.
// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-security_impersonation_level
const (
	SecurityAnonymous uint32 = iota
	SecurityIdentification
	SecurityImpersonation
	SecurityDelegation
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

const (
	MAXIMUM_ALLOWED uint32 = 0x02000000
)

// Functions

// AdjustTokenPrivilegesN enables or disables privileges in the specified access token.
// Enabling or disabling privileges in an access token requires TOKEN_ADJUST_PRIVILEGES access.
// The "N" in the function name is for Native as it avoids using external packages
// https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
func AdjustTokenPrivilegesN(hToken windows.Token, disable bool, priv string) (err error) {
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

// CreateProcessWithLogonG Creates a new process and its primary thread.
// Then the new process runs the specified executable file in the security context of the specified credentials
// (user, domain, and password). It can optionally load the user profile for a specified user.
// The "N" in the function name is for Native as it avoids using external packages
// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw
func CreateProcessWithLogonG(lpUsername *uint16, lpDomain *uint16, lpPassword *uint16, dwLogonFlags uint32, lpApplicationName *uint16, lpCommandLine *uint16, dwCreationFlags uint32, lpEnvironment uintptr, lpCurrentDirectory *uint16, lpStartupInfo *windows.StartupInfo, lpProcessInformation *windows.ProcessInformation) error {
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
	ret, _, err := CreateProcessWithLogon.Call(
		uintptr(unsafe.Pointer(lpUsername)),
		uintptr(unsafe.Pointer(lpDomain)),
		uintptr(unsafe.Pointer(lpPassword)),
		uintptr(dwLogonFlags),
		uintptr(unsafe.Pointer(lpApplicationName)),
		uintptr(unsafe.Pointer(lpCommandLine)),
		uintptr(dwCreationFlags),
		lpEnvironment,
		uintptr(unsafe.Pointer(lpCurrentDirectory)),
		uintptr(unsafe.Pointer(lpStartupInfo)),
		uintptr(unsafe.Pointer(lpProcessInformation)),
	)
	if err != syscall.Errno(0) || ret == 0 {
		return fmt.Errorf("there was an error calling CreateProcessWithLogon with return code %d: %s", ret, err)
	}
	return nil
}

// CreateProcessWithLogonN Creates a new process and its primary thread.
// Then the new process runs the specified executable file in the security context of the specified credentials
// (user, domain, and password). It can optionally load the user profile for a specified user.
// The "G" at the end of the function name is for Golang because it uses the golang.org/x/sys/windows Go package
// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw
func CreateProcessWithLogonN(lpUsername *uint16, lpDomain *uint16, lpPassword *uint16, dwLogonFlags uint32, lpApplicationName *uint16, lpCommandLine *uint16, dwCreationFlags uint32, lpEnvironment uintptr, lpCurrentDirectory *uint16, lpStartupInfo *StartupInfo, lpProcessInformation *ProcessInformation) error {
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

	// Parse optional arguments
	var domain uintptr
	if *lpDomain == 0 {
		domain = 0
	} else {
		domain = uintptr(unsafe.Pointer(lpDomain))
	}

	var applicationName uintptr
	if *lpApplicationName == 0 {
		applicationName = 0
	} else {
		applicationName = uintptr(unsafe.Pointer(lpApplicationName))
	}

	var commandLine uintptr
	if *lpCommandLine == 0 {
		commandLine = 0
	} else {
		commandLine = uintptr(unsafe.Pointer(lpCommandLine))
	}

	var currentDirectory uintptr
	if *lpCurrentDirectory == 0 {
		currentDirectory = 0
	} else {
		currentDirectory = uintptr(unsafe.Pointer(lpCurrentDirectory))
	}

	ret, _, err := CreateProcessWithLogon.Call(
		uintptr(unsafe.Pointer(lpUsername)),
		domain,
		uintptr(unsafe.Pointer(lpPassword)),
		uintptr(dwLogonFlags),
		applicationName,
		commandLine,
		uintptr(dwCreationFlags),
		lpEnvironment,
		currentDirectory,
		uintptr(unsafe.Pointer(lpStartupInfo)),
		uintptr(unsafe.Pointer(lpProcessInformation)),
	)
	if err != syscall.Errno(0) || ret == 0 {
		return fmt.Errorf("there was an error calling CreateProcessWithLogon with return code %d: %s", ret, err)
	}
	return nil
}

// CreateProcessWithTokenN Creates a new process and its primary thread.
// The new process runs in the security context of the specified token.
// It can optionally load the user profile for the specified user.
// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw
func CreateProcessWithTokenN(hToken *unsafe.Pointer, dwLogonFlags uint32, lpApplicationName *uint16, lpCommandLine *uint16, dwCreationFlags uint32, lpEnvironment uintptr, lpCurrentDirectory *uint16, lpStartupInfo *StartupInfo, lpProcessInformation *ProcessInformation) error {
	CreateProcessWithToken := Advapi32.NewProc("CreateProcessWithTokenW")
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

	// Parse optional arguments
	var applicationName uintptr
	if *lpApplicationName == 0 {
		applicationName = 0
	} else {
		applicationName = uintptr(unsafe.Pointer(lpApplicationName))
	}

	var commandLine uintptr
	if *lpCommandLine == 0 {
		commandLine = 0
	} else {
		commandLine = uintptr(unsafe.Pointer(lpCommandLine))
	}

	var currentDirectory uintptr
	if *lpCurrentDirectory == 0 {
		currentDirectory = 0
	} else {
		currentDirectory = uintptr(unsafe.Pointer(lpCurrentDirectory))
	}

	ret, _, err := CreateProcessWithToken.Call(
		uintptr(*hToken),
		uintptr(dwLogonFlags),
		applicationName,
		commandLine,
		uintptr(dwCreationFlags),
		lpEnvironment,
		//uintptr(unsafe.Pointer(lpCurrentDirectory)),
		currentDirectory,
		uintptr(unsafe.Pointer(lpStartupInfo)),
		uintptr(unsafe.Pointer(lpProcessInformation)),
	)
	if err != syscall.Errno(0) || ret == 0 {
		return fmt.Errorf("there was an error calling advapi32!CreateProcessWithTokenW with return code %d: %s", ret, err)
	}
	return nil
}

// DuplicateToken creates a new access token that duplicates one already in existence.
// https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetoken
func DuplicateToken(hToken windows.Token) (token windows.Token, err error) {
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

// DuplicateTokenN function creates a new access token that duplicates an existing token.
// This function can create either a primary token or an impersonation token.
// The "N" in the function name is for Native as it avoids using external packages
// https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex
func DuplicateTokenN(hExistingToken *unsafe.Pointer, dwDesiredAccess uint32, ImpersonationLevel uint32, TokenType uint32) (*unsafe.Pointer, error) {
	DuplicateTokenEx := Advapi32.NewProc("DuplicateTokenEx")

	// BOOL DuplicateTokenEx(
	//  [in]           HANDLE                       hExistingToken,
	//  [in]           DWORD                        dwDesiredAccess,
	//  [in, optional] LPSECURITY_ATTRIBUTES        lpTokenAttributes,
	//  [in]           SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
	//  [in]           TOKEN_TYPE                   TokenType,
	//  [out]          PHANDLE                      phNewToken
	//);

	var phNewToken unsafe.Pointer
	ret, _, err := DuplicateTokenEx.Call(uintptr(*hExistingToken), uintptr(dwDesiredAccess), 0, uintptr(ImpersonationLevel), uintptr(TokenType), uintptr(unsafe.Pointer(&phNewToken)))
	if err != syscall.Errno(0) || ret == 0 {
		return nil, fmt.Errorf("there was an error calling Advapi32!DuplicateTokenEx with return code %d: %s", ret, err)
	}
	return &phNewToken, nil
}

// GetTokenInformationN retrieves a specified type of information about an access token
// The calling process must have appropriate access rights to obtain the information.
// The caller is responsible for marshalling the bytes into the appropriate structure
// The "N" in the function name is for Native as it avoids using external packages
// https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation
func GetTokenInformationN(TokenHandle *unsafe.Pointer, TokenInformationClass uint32) (TokenInformation *bytes.Buffer, ReturnLength uint32, err error) {
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

// ImpersonateLoggedOnUserG lets the calling thread impersonate the security context of a logged-on user.
// The user is represented by a token handle.
// The "G" at the end of the function name is for Golang because it uses the golang.org/x/sys/windows Go package
// https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-impersonateloggedonuser
func ImpersonateLoggedOnUserG(hToken windows.Token) (err error) {
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

// LookupPrivilegeName retrieves the name that corresponds to the privilege represented on a specific system by a
// specified locally unique identifier (LUID).
// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegenamew
func LookupPrivilegeName(luid LUID) (privilege string, err error) {
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

// LogonUser attempts to log a user on to the local computer.
// The local computer is the computer from which LogonUser was called. You cannot use LogonUser to log on to a remote computer.
// You specify the user with a user name and domain and authenticate the user with a plaintext password.
// If the function succeeds, you receive a handle to a token that represents the logged-on user.
// You can then use this token handle to impersonate the specified user or, in most cases, to create a process that runs in the context of the specified user.
// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw
func LogonUser(lpszUsername *uint16, lpszDomain *uint16, lpszPassword *uint16, dwLogonType uint32, dwLogonProvider uint32) (token *unsafe.Pointer, err error) {
	// The LogonUser function was not available in the golang.org/x/sys/windows package at the time of writing
	LogonUserW := Advapi32.NewProc("LogonUserW")

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
		uintptr(unsafe.Pointer(lpszUsername)),
		uintptr(unsafe.Pointer(lpszDomain)),
		uintptr(unsafe.Pointer(lpszPassword)),
		uintptr(dwLogonType),
		uintptr(dwLogonProvider),
		uintptr(unsafe.Pointer(&phToken)),
	)
	if err != syscall.Errno(0) {
		err = fmt.Errorf("there was an error calling advapi32!LogonUserW: %s", err)
		return
	}
	return &phToken, nil
}

// OpenProcessTokenN opens the access token associated with a process
// The "N" in the function name is for Native as it avoids using external packages
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
func OpenProcessTokenN(ProcessHandle *unsafe.Pointer, DesiredAccess int) (token *unsafe.Pointer, err error) {
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

// OpenThreadTokenN opens the access token associated with a thread.
// The "N" in the function name is for Native as it avoids using external packages
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthreadtoken
func OpenThreadTokenN(ThreadHandle *unsafe.Pointer, DesiredAccess uint32, OpenAsSelf bool) (hToken *unsafe.Pointer, err error) {
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

// PrivilegeCheckN determines whether a specified set of privileges are enabled in an access token
// The "N" in the function name is for Native as it avoids using external packages
// https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-privilegecheck
func PrivilegeCheckN(hToken *unsafe.Pointer, privs PRIVILEGE_SET) (hasPriv bool, err error) {
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
	return
}

// RevertToSelfN terminates the impersonation of a client application
// https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself
func RevertToSelfN() (err error) {
	RevertToSelf := Advapi32.NewProc("RevertToSelf")

	ret, _, err := RevertToSelf.Call()
	if err != syscall.Errno(0) || ret == 0 {
		err = fmt.Errorf("there was an error calling Advapi32!RevertToSelf with return code %d: %s", ret, err)
		return
	}
	return nil
}

// SetThreadToken assigns an impersonation token to a thread.
// The function can also cause a thread to stop using an impersonation token.
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadtoken
func SetThreadToken(Thread, Token unsafe.Pointer) error {
	SetThreadToken := Advapi32.NewProc("SetThreadToken")

	// BOOL SetThreadToken(
	//  [in, optional] PHANDLE Thread,
	//  [in, optional] HANDLE  Token
	//);
	_, _, err := SetThreadToken.Call(uintptr(Thread), uintptr(Token))
	if err != syscall.Errno(0) {
		return fmt.Errorf("there was an error calling advapi32!SetThreadToken: %s", err)
	}
	return nil
}

// Structures

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

// ProcessInformation Contains information about a newly created process and its primary thread.
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information
// https://pkg.go.dev/golang.org/x/sys/windows#ProcessInformation
type ProcessInformation struct {
	Process   uintptr
	Thread    uintptr
	ProcessId uint32
	ThreadId  uint32
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
