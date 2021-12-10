# Oddments

Oddments is a repository of random code snippets used to develop proof of concepts for techniques used with the 
Windows operating system.

## POCs

- [HideConsole](./cmd/HideConsole/README.md) - Hide a console window so it isn't visible to users
- [ListPrivs](./cmd/ListPrivs/README.md) - Lists current privileges associated with a **Primary** process token
- [MakeToken](./cmd/MakeToken/README.md) - Create a Windows Access Token for another user and use it to remotely list the files on a remote host
- [RunAs](./cmd/RunAs/README.md) - Run a program as another user; Includes _netonly_ functionality
- [StealToken](./cmd/StealToken/README.md) - Steal a Windows Access Token from another process
- [SSHClient](./cmd/SSHClient/README.md) - Execute commands and retrieve output through SSH (non-interactive)

## Library

- [pkg](./pkg) - Wrapper functions for interacting with the Windows API
  - [privs](./pkg/privs) - Functions dealing with Windows [Privileges](https://docs.microsoft.com/en-us/windows/win32/secauthz/privileges)
  - [process](./pkg/process) - Functions for working with Windows processes
  - [tokens](./pkg/tokens) - Function for working with Windows [Access Tokens](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [windows](./windows) - Windows API functions
  - [advapi32](./windows/advapi32) - Windows API functions exported in `Advapi32.dll`
  - [kernel32](./windows/kernel32) - Windows API functions exported in `kernel32.dll`
  - [user32](./windows/user32) - Windows API functions exported in `user32.dll`