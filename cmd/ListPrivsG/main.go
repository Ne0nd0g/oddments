// +build windows

// List token privileges

package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"golang.org/x/sys/windows"
	"log"
	"oddments/windows/tokens"
	"os"
	"syscall"
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

	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, true, uint32(*pid))
	if err != nil {
		log.Fatal(fmt.Sprintf("there was an error calling windows.OpenProcess(): %s", err))
	}
	if verbose {
		fmt.Printf("[-] Current process handle: 0x%X\n", hProc)
	}

	// Close the handle when done
	defer func() {
		if debug {
			fmt.Println("[DEBUG] Calling windows.CloseHandle()...")
		}
		err := windows.CloseHandle(hProc)
		if err != nil{
			log.Fatal(fmt.Sprintf("there was an error calling windows.CloseHandle() for the process: %s", err))
		}
		if verbose {
			fmt.Println("[-] Closed the process handle without error")
		}
	}()

	// Use process handle to get a token
	if debug {
		fmt.Println("[DEBUG] Calling windows.OpenProcessToken()...")
	}
	var token windows.Token
	err = windows.OpenProcessToken(hProc, windows.TOKEN_QUERY, &token)
	if err != nil {
		log.Fatal(fmt.Sprintf("there was an error calling windows.OpenProcessToken(): %s", err))
	}
	if verbose {
		fmt.Printf("[-] Current process token handle: 0x%X\n", token)
	}
	// Close the handle when done
	defer func() {
		if debug {
			fmt.Println("[DEBUG] Closing the token handle...")
		}
		err := token.Close()
		if err != nil {
			log.Fatal(fmt.Sprintf("there was an error calling token.Close(): %s", err))
		}
		if verbose {
			fmt.Println("[-] Closed the token handle without error")
		}
	}()

	// Call to get structure size
	var returnedLen uint32
	if debug {
		fmt.Println("[DEBUG] Calling windows.GetTokenInformation() to determine TokenInformation structure size...")
	}
	err = windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &returnedLen)
	if err != syscall.ERROR_INSUFFICIENT_BUFFER {
		log.Fatal(fmt.Sprintf("there was an error calling windows.GetTokenInformation: %s", err))
	}
	if verbose {
		fmt.Printf("[-] TokenInformation structure size: %d\n", returnedLen)
	}

	// Call again to get the actual structure
	info := bytes.NewBuffer(make([]byte, returnedLen))
	if debug {
		fmt.Println("[DEBUG] Calling windows.GetTokenInformation() to get TokenPrivileges structure...")
	}
	err = windows.GetTokenInformation(token, windows.TokenPrivileges, &info.Bytes()[0], returnedLen, &returnedLen)
	if err != nil {
		log.Fatal(fmt.Sprintf("there was an error calling windows.GetTokenInformation: %s", err))
	}

	if debug {
		fmt.Println("[DEBUG] Reading TokenPrivileges bytes to privilegeCount...")
	}

	var privilegeCount uint32
	err = binary.Read(info, binary.LittleEndian, &privilegeCount)
	if err != nil {
		log.Fatal(fmt.Sprintf("there was an error reading TokenPrivileges bytes to privilegeCount: %s", err))
	}
	if verbose {
		fmt.Printf("[-] Token privilege count: %+v\n", privilegeCount)
	}

	// Read in the LUID and Attributes
	var privs []windows.LUIDAndAttributes
	for i := 1; i <= int(privilegeCount); i++ {
		var priv windows.LUIDAndAttributes
		err = binary.Read(info, binary.LittleEndian, &priv)
		if err != nil {
			log.Fatal(fmt.Sprintf("there was an error reading LUIDAttributes to bytes: %s", err))
		}
		privs = append(privs, priv)
	}

	fmt.Printf("[+] Process ID %d access token privileges:\n", *pid)
	for _, v := range privs {
		var luid tokens.LUID
		luid.HighPart = v.Luid.HighPart
		luid.LowPart = v.Luid.LowPart
		p, err := tokens.LookupPrivilegeName(luid)
		if err != nil{
			log.Fatal(err)
		}
		fmt.Printf("[+] Privilege: %s, Attribute: %s\n", p, tokens.PrivilegeAttributeToString(v.Attributes))
	}



}
