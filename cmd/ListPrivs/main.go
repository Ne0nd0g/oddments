// +build windows

// List token privileges

package main

import (
	// Standard
	"encoding/binary"
	"flag"
	"fmt"
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
	pid := flag.Int("pid", 0, "The process ID to steal a token from. Defaults to current process")
	flag.Usage = func() {
		flag.PrintDefaults()
		os.Exit(0)
	}
	flag.Parse()

	if *pid == 0 {
		*pid = os.Getpid()
		if verbose {
			fmt.Printf("[-] Using current proccess ID: %d\n", *pid)
		}
	}

	// 1. Get the current process token
	// Get a handle to the current process
	if debug {
		fmt.Println("[DEBUG] Calling windows.OpenProcess()...")
	}
	var PROCESS_QUERY_INFORMATION uint32 = 0x0400
	hProc, err := kernel32.OpenProcessN(uint32(*pid), PROCESS_QUERY_INFORMATION, true)
	if err != nil {
		log.Fatal(err)
	}
	if verbose {
		fmt.Printf("[-] Current process handle: 0x%X\n", hProc)
	}

	// Close the handle when done
	defer func() {
		if debug {
			fmt.Println("[DEBUG] Calling tokens.CloseHandleN()...")
		}
		err := kernel32.CloseHandleN(hProc)
		if err != nil {
			log.Fatal(fmt.Sprintf("there was an error calling tokens.CloseHandleN() for the process: %s", err))
		}
		if verbose {
			fmt.Println("[-] Closed the process handle without error")
		}
	}()

	// Use process handle to get a token
	if debug {
		fmt.Println("[DEBUG] Calling tokens.OpenProcessTokenN()...")
	}
	var TOKEN_QUERY int = 0x0008
	token, err := advapi32.OpenProcessTokenN(hProc, TOKEN_QUERY)
	if err != nil {
		log.Fatal(fmt.Sprintf("there was an error calling tokens.OpenProcessTokenN(): %s", err))
	}
	if verbose {
		fmt.Printf("[-] Current process token handle: 0x%X\n", token)
	}

	// Close the handle when done
	defer func() {
		if debug {
			fmt.Println("[DEBUG] Closing the token handle...")
		}
		err := kernel32.CloseHandleN(token)
		if err != nil {
			log.Fatal(fmt.Sprintf("there was an error calling tokens.CloseHandleN(): %s", err))
		}
		if verbose {
			fmt.Println("[-] Closed the token handle without error")
		}
	}()

	// Get token integrity level
	if debug {
		fmt.Println("[DEBUG] Calling tokens.GetTokenInformation() for TokenIntegrityLevel")
	}
	var TokenIntegrityLevel uint32 = 25
	TokenIntegrityInformation, ReturnLength, err := advapi32.GetTokenInformationN(token, TokenIntegrityLevel)
	if err != nil {
		log.Fatal(fmt.Sprintf("there was an error calling tokens.GetTokenInformationN: %s", err))
	}

	// Read the buffer into a byte slice
	bLabel := make([]byte, ReturnLength)
	err = binary.Read(TokenIntegrityInformation, binary.LittleEndian, &bLabel)
	if err != nil {
		log.Fatal(fmt.Sprintf("there was an error reading bytes for the token integrity level: %s", err))
	}

	// Integrity level is in the Attributes portion of the structure, a DWORD, the last four bytes
	// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_mandatory_label
	// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-sid_and_attributes
	integrityLevel := binary.LittleEndian.Uint32(bLabel[ReturnLength-4:])

	// Get token privileges and attributes
	if debug {
		fmt.Println("[DEBUG] Calling tokens.GetTokenInformationN() for TokenPrivileges...")
	}
	var TokenPrivileges uint32 = 0x0003
	TokenInformation, ReturnLength, err := advapi32.GetTokenInformationN(token, TokenPrivileges)
	if err != nil {
		log.Fatal(fmt.Sprintf("there was an error calling tokens.GetTokenInformationN: %s", err))
	}
	if verbose {
		fmt.Printf("[-] Recieved TokenInformation buffer of size %d\n", ReturnLength)
	}

	if debug {
		fmt.Println("[DEBUG] Reading TokenPrivileges bytes to privilegeCount...")
	}
	var privilegeCount uint32
	err = binary.Read(TokenInformation, binary.LittleEndian, &privilegeCount)
	if err != nil {
		log.Fatal(fmt.Sprintf("there was an error reading TokenPrivileges bytes to privilegeCount: %s", err))
	}
	if verbose {
		fmt.Printf("[-] Token privilege count: %+v\n", privilegeCount)
	}

	// Read in the LUID and Attributes
	var privs []advapi32.LUID_AND_ATTRIBUTES
	for i := 1; i <= int(privilegeCount); i++ {
		var priv advapi32.LUID_AND_ATTRIBUTES
		err = binary.Read(TokenInformation, binary.LittleEndian, &priv)
		if err != nil {
			log.Fatal(fmt.Sprintf("there was an error reading LUIDAttributes to bytes: %s", err))
		}
		privs = append(privs, priv)
	}

	if debug {
		fmt.Printf("[DEBUG] Privilege LUID_AND_ATTRIBUTES:\n%+v", privs)
	}

	fmt.Printf(
		"[+] Process ID %d access token integrity level: %s, privileges (%d):\n",
		*pid, tokens.IntegrityLevelToString(integrityLevel), privilegeCount,
	)
	for _, v := range privs {
		p, err := advapi32.LookupPrivilegeName(v.Luid)
		if err != nil {
			log.Fatal(err)
		}
		a := tokens.PrivilegeAttributeToString(v.Attributes)
		if a == "" {
			fmt.Printf("[+] %s\n", p)
		} else {
			fmt.Printf("[+] %s (%s)\n", p, a)
		}
	}
}
