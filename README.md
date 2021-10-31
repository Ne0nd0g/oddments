# Oddments

Oddments is a repository of random code snippets used to develop proof of concepts for techniques used with the 
Windows operating system.

## POCs

- [ListPrivs](./cmd/ListPrivs/README.md) - Lists current privileges associated with a **Primary** process token
- [MakeToken](./cmd/MakeToken/README.md) - Create a Windows Access Token for another user and use it to remotely list the files on a remote host
- [RunAs](./cmd/RunAs/README.md) - Run a program as another user; Includes _netonly_ functionality
- [StealToken](./cmd/StealToken/README.md) - Steal a Windows Access Token from another process