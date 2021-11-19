# StealToken

This program "steals" a Windows Access Token from another running process and applies it to the current process.
You must have enough privilege and permissions to gain a handle to the target process.

The following Windows APIs are used:

* [OpenProcess](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)
  * Get a handle to the target process
* [OpenProcessToken](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken)
  * Get a handle to the target process' access token
* [ImpersonateLoggedOnUser](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-impersonateloggedonuser)
    * Applies the stolen Impersonation token to the current process, so it can be used to impersonate the user
* [GetTokenInformation](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation)
    * Retrieve [TokenStatistics](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_statistics)
* [DuplicateTokenEx](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex)
  * Convert a stolen impersonation token to a primary token
* [CreateProcessWithTokenW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw)
  * Start a process with the stolen and duplicated token 
* [RevertToSelf](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself)
    * Release the Impersonation token so that the current process is no longer using it

## Usage

```text
  -args string
        Arguments to run the process with (default "/k whoami /all")
  -create
        Create a new process with stolen token
  -debug
        Enable debug output
  -path string
        A network file share UNC path to retrieve the contents of with the stolen token (default "\\\\127.0.0.1\\ADMIN$")
  -pid uint
        The process ID to steal a token from
  -process string
        The process to run as the provided user (default "cmd.exe")
  -verbose
        Enable verbose output
```

## Compile

From the project root, run `go build -o StealToken.exe cmd/StealToken/main.go` to compile the program.
