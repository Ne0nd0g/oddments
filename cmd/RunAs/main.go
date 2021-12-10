// +build windows

package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	// Oddments Internal
	"github.com/Ne0nd0g/oddments/pkg/process"
	"github.com/Ne0nd0g/oddments/windows/advapi32"
)

var verbose bool
var debug bool

func main() {
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output")
	flag.BoolVar(&debug, "debug", false, "Enable debug output")
	user := flag.String("user", "", "Username to run the new process as")
	pass := flag.String("password", "", "The user's password")
	proc := flag.String("process", "cmd.exe", "The process to run as the provided user")
	args := flag.String("args", "", "Arguments to start the process with")
	netonly := flag.Bool("netonly", false, "use if the credentials specified are for remote access only")
	flag.Usage = func() {
		flag.PrintDefaults()
		os.Exit(0)
	}
	flag.Parse()

	if *user == "" || *pass == "" || *proc == "" {
		flag.Usage()
	}

	if verbose {
		fmt.Printf("[-] Creating process %s as %s with a password of %s\n", *proc, *user, *pass)
	}

	logonType := advapi32.LOGON_WITH_PROFILE
	if *netonly {
		logonType = advapi32.LOGON_NETCREDENTIALS_ONLY
	}

	procInfo, err := process.CreateProcessWithLogonN(*user, "", *pass, *proc, *args, logonType, false)
	if err != nil {
		log.Fatal(err)
	}

	if debug {
		fmt.Printf("[DEBUG] Process information: %+v\n", procInfo)
	}
	fmt.Printf("[+] Created %s process with an ID of %d as %s", *proc, procInfo.ProcessId, *user)
}
