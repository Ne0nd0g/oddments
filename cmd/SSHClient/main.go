package main

import (
	// Standard
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"

	// X Package
	"golang.org/x/crypto/ssh"
)

var verbose bool
var debug bool

// Hard code arguments here
var user = "root"
var pass = "password"
var host = "127.0.0.1"
var port = "22"
var command = "whoami"

func main() {
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output")
	flag.BoolVar(&debug, "debug", false, "Enable debug output")
	flag.StringVar(&user, "user", user, "Username to run the new process as")
	flag.StringVar(&pass, "pass", pass, "The user's password")
	flag.StringVar(&host, "host", host, "The target hostname or IP")
	flag.StringVar(&port, "port", port, "The target SSH service port")
	flag.StringVar(&command, "command", command, "Command to execute on the remote host over SSH")
	flag.Usage = func() {
		flag.PrintDefaults()
		os.Exit(0)
	}
	flag.Parse()

	if user == "" || pass == "" || host == "" {
		flag.Usage()
	}

	stdout, stderr, err := DialWithPassword(user, pass, host, port, command)
	if err != nil {
		log.Fatal(err)
	}
	if stdout != "" {
		fmt.Printf("[STDOUT]\n%s\n", stdout)
	}
	if stderr != "" {
		fmt.Printf("[STDERR]\n%s\n", stderr)
	}
}

func DialWithPassword(user, pass, host, port, command string) (stdout, stderr string, err error) {
	if user == "" {
		err = fmt.Errorf("A username must be provided when calling DialWithPassword()")
		return
	}
	if pass == "" {
		err = fmt.Errorf("A password must be provided when calling DialWithPassword()")
		return
	}
	if host == "" {
		err = fmt.Errorf("A hostname or IP address must be provided when calling DialWithPassword()")
		return
	}
	if port == "" {
		err = fmt.Errorf("A target port must be provided when calling DialWithPassword()")
		return
	}
	if command == "" {
		err = fmt.Errorf("A command must be provided when calling DialWithPassword()")
		return
	}

	// Validate port is a number
	_, err = strconv.Atoi(port)
	if err != nil {
		err = fmt.Errorf("there was an error converting the port to an integer: %s", err)
		return
	}
	addr := fmt.Sprintf("%s:%s", host, port)

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}

	sshClient, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		err = fmt.Errorf("there was an error calling ssh.Dial: %s", err)
		return
	}

	defer func() {
		err := sshClient.Close()
		if err != nil {
			fmt.Printf("there was an error closing the SSH client: %s\n", err)
		}
	}()

	sshSession, err := sshClient.NewSession()
	if err != nil {
		err = fmt.Errorf("there was an error calling SSH Client NewSession(): %s", err)
		return
	}

	defer func() {
		err := sshSession.Close()
		if err != nil && err != io.EOF {
			fmt.Printf("there was an error closing the SSH session: %s\n", err)
		}
	}()

	var stdoutBuffer bytes.Buffer
	var stderrBuffer bytes.Buffer

	sshSession.Stdout = io.Writer(&stdoutBuffer)
	sshSession.Stderr = io.Writer(&stderrBuffer)

	err = sshSession.Run(command)
	if err != nil {
		err = fmt.Errorf("there was an error calling SSH Session Run(): %s", err)
	}

	stdout = stdoutBuffer.String()
	stderr = stderrBuffer.String()
	return
}
