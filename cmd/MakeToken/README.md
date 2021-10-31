# MakeToken

This program creates a new Access Token for the provided credentials and applies the created token to the thread. 
A [Windows Security Log Event ID 4624](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4624) 
is created for the specified user and uses a logon type 9 logon (LOGON32_LOGON_NEW_CREDENTIALS).

The following Windows APIs are used:

* [LogonUserW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw)
  * Creates an [Impersonation Token](https://docs.microsoft.com/en-us/windows/win32/secauthz/impersonation-tokens) with an [Impersonation Level](https://docs.microsoft.com/en-us/windows/win32/secauthz/impersonation-levels) of `SecurityImpersonation`
* [ImpersonateLoggedOnUser](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-impersonateloggedonuser)
  * Applies the created Impersonation token to the current process, so it can be used to impersonate the user
* [GetTokenInformation](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation)
  * Retrieve [TokenStatistics](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_statistics)
* [RevertToSelf](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself)
  * Release the Impersonation token so that the current process is no longer using it


## Usage

```text
  -debug
        Enable debug output
  -domain string
        The user's domain (optional)
  -password string
        The user's password
  -path string
        A network file share UNC path to retrieve the contents of with the new thread token (default "\\\\127.0.0.1\\ADMIN$")
  -user string
        Username to run the new process as
  -verbose
        Enable verbose output
```

## Compile

From the project root, run `go build -o MakeToken.exe cmd/MakeToken/main.go`, to compile the program.
