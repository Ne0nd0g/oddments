# SSHClient

This program is used to execute commands on a remote host through SSH and retrieve the output.
This is asynchronous and is **NOT** an interactive SSH client.

The command line arguments can be hard-coded into variables at the top of the file. 
This is useful to run the program without having to provide command line arguments.

## Usage

```text
  -command string
        Command to execute on the remote host over SSH (default "whoami")
  -debug
        Enable debug output
  -host string
        The target hostname or IP (default "127.0.0.1")
  -pass string
        The user's password (default "password")
  -port string
        The target SSH service port (default "22")
  -user string
        Username to run the new process as (default "root")
  -verbose
        Enable verbose output
```

## Example

```text
go run cmd/SSHClient/main.go -user rastley -pass N3verGonnaGiveYouUp -host 192.168.100.17 -port 22 -command "whoami && date"
there was an error closing the SSH session: EOF
[STDOUT]
rastley
Tue 07 Dec 2021 03:44:23 AM UTC
```

## Compile

From the project root, run `go build -o SSHClient.exe cmd/SSHClient/main.go`, to compile the program.