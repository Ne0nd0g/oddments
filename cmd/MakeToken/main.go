// +build windows

package main

import (
	// Standard
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	// Oddments Internal
	"github.com/Ne0nd0g/oddments/pkg/tokens"
	"github.com/Ne0nd0g/oddments/windows/advapi32"
	"github.com/Ne0nd0g/oddments/windows/kernel32"
)

var verbose bool
var debug bool

func main() {
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output")
	flag.BoolVar(&debug, "debug", false, "Enable debug output")
	user := flag.String("user", "", "Username to run the new process as")
	pass := flag.String("password", "", "The user's password")
	domain := flag.String("domain", "", "The user's domain (optional)")
	path := flag.String("path", "\\\\127.0.0.1\\ADMIN$", "A network file share UNC path to retrieve the contents of with the new thread token")
	flag.Usage = func() {
		flag.PrintDefaults()
		os.Exit(0)
	}
	flag.Parse()

	if *user == "" || *pass == "" {
		flag.Usage()
	}

	// Make token
	if debug {
		fmt.Printf("[DEBUG] Calling LogonUser to create a new type 9 logon session for %s...\n", *user)
	}
	token, err := tokens.LogonUserN(*user, *pass, *domain, advapi32.LOGON32_LOGON_NEW_CREDENTIALS, advapi32.LOGON32_PROVIDER_DEFAULT)
	if err != nil {
		log.Fatal(err)
	}
	if verbose {
		fmt.Printf("[+] Successfully created a new type 9 logon session for %s\n", *user)
	}

	// Set token
	if debug {
		fmt.Printf("[DEBUG] Calling ImpersonateLoggedOnUser...\n")
	}
	err = advapi32.ImpersonateLoggedOnUserN(token)
	if err != nil {
		log.Fatal(err)
	}
	if verbose {
		fmt.Printf("[+] Successfully applied impersonation token for %s\n", *user)
	}

	// Display token information
	if debug {
		fmt.Printf("[DEBUG] Retrieving Primary and Impersonation token information...\n")
	}
	whoami, err := tokens.WhoamiN()
	if err != nil {
		log.Fatal(err)
	}
	if verbose {
		fmt.Printf("[-] Token WhoAmI:\n%s\n", whoami)
	}

	// Use the new thread token to list the contents of a remote file share
	// This should be a resource that the process token can't access, but the threat token can
	if debug {
		fmt.Printf("[DEBUG] Using impersonation token remotely list the contents of %s...\n", *path)
	}
	files, err := ioutil.ReadDir(*path)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\nDirectory listing for %s\n\n", *path)
	for _, file := range files {
		fmt.Printf("%s\t%d\t%s\n", file.Mode(), file.Size(), file.Name())
	}
	fmt.Println()

	// Drop the token
	if debug {
		fmt.Println("[DEBUG] Calling RevertToSelf to remove the impersonation token...")
	}
	err = advapi32.RevertToSelfN()
	if err != nil {
		log.Fatal(err)
	}
	if verbose {
		fmt.Println("[-] Impersonation token released")
	}

	// Close the handle
	if debug {
		fmt.Println("[DEBUG] Calling CloseHandle to release the impersonation token handle...")
	}
	err = kernel32.CloseHandleN(token)
	if err != nil {
		log.Fatal(err)
	}
	if verbose {
		fmt.Println("[-] Impersonation token handle closed")
	}

	// Display token information
	if debug {
		fmt.Printf("[DEBUG] Retrieving Primary and Impersonation token information...\n")
	}
	whoami, err = tokens.WhoamiG()
	if err != nil {
		log.Fatal(err)
	}
	if verbose {
		fmt.Printf("[-] Token WhoAmI:\n%s\n", whoami)
	}
}
