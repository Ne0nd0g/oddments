# ListPrivs

This program will list the privileges and integrity level associated with a Windows **Primary** access token.
If a `-pid` argument is not provided, privileges for the current process will be displayed.
You must have enough permissions to get a handle to the target process

## Usage

```text
PS Z:\> Z:\Share\ListPrivs.exe -h
  -debug
        Enable debug output
  -pid int
        The process ID to steal a token from. Defaults to current process
  -verbose
        Enable verbose output
```


## Example

```text
PS Z:\> .\ListPrivs.exe
[+] Process ID 7956 access token integrity level: Medium, privileges (5):
[+] SeShutdownPrivilege
[+] SeChangeNotifyPrivilege (SE_PRIVILEGE_ENABLED_BY_DEFAULT,SE_PRIVILEGE_ENABLED)
[+] SeUndockPrivilege
[+] SeIncreaseWorkingSetPrivilege
[+] SeTimeZonePrivilege
```

## WIN API

The following Windows API calls are used:

- [OpenProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)
  - Get a handle to the process
- [OpenProcessToken](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken)
  - Get a handle to the access token
- [CloseHandle](https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle)
  - Close the process and access token handles
- [GetTokenInformation](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation)
  - Get the access token integrity level with `TokenIntegrityLevel`
  - Get the access token privileges with `TokenPrivileges`
- [LookUpPrivilegeNameW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegenamew)
  - Convert a privilege LUID to a string
