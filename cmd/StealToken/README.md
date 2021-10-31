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
* [RevertToSelf](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself)
    * Release the Impersonation token so that the current process is no longer using it
