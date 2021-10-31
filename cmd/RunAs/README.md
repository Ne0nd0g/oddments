# RunAs

This program runs a program as a different user. The provided credentials will be used to create a logon session for the user.
By default, the provided credentials will be validated and will fail if incorrect.
The `-netonly` flag will not validate the credentials during process creation; they will only be used when remotely authenticating to a network resource

The following Windows APIs are used:

* [CreateProcessWithLogon](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithlogonw)
    > Creates a new process and its primary thread. Then the new process runs the specified executable file in the security context of the specified credentials (user, domain, and password).

## Usage

```text
  -args string
        Arguments to start the process with
  -debug
        Enable debug output
  -netonly
        use if the credentials specified are for remote access only
  -password string
        The user's password
  -process string
        The process to run as the provided user (default "cmd.exe")
  -user string
        Username to run the new process as
  -verbose
        Enable verbose output
```

## Compile

From the project root, run `go build -o RunAs.exe cmd/RunAs/main.go` to compile the program.