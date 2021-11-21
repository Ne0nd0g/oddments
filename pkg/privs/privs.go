// +build windows

// Package privs contains wrapper functions that interact with Windows Access Tokens
// Many of the functions are used to enumerate privs and return them as a string

package privs

import (
	// Standard
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"

	// X Packages
	"golang.org/x/sys/windows"

	// Oddments Internal
	"oddments/pkg/tokens"
	"oddments/windows/advapi32"
)

// GetPrivileges enumerates the privileges and attributes for the provided access token handle
// and returns them as a slice of strings
func GetPrivileges(token *unsafe.Pointer) (privileges []string, err error) {
	TokenInformation, _, err := advapi32.GetTokenInformationN(token, advapi32.TokenPrivileges)
	if err != nil {
		err = fmt.Errorf("there was an error calling tokens.GetTokenInformationN: %s", err)
		return
	}

	var privilegeCount uint32
	err = binary.Read(TokenInformation, binary.LittleEndian, &privilegeCount)
	if err != nil {
		err = fmt.Errorf("there was an error reading TokenPrivileges bytes to privilegeCount: %s", err)
		return
	}

	// Read in the LUID and Attributes
	var privs []advapi32.LUID_AND_ATTRIBUTES
	for i := 1; i <= int(privilegeCount); i++ {
		var priv advapi32.LUID_AND_ATTRIBUTES
		err = binary.Read(TokenInformation, binary.LittleEndian, &priv)
		if err != nil {
			err = fmt.Errorf("there was an error reading LUIDAttributes to bytes: %s", err)
			return
		}
		privs = append(privs, priv)
	}

	// Convert to string equivalents
	for _, v := range privs {
		p, err := advapi32.LookupPrivilegeName(v.Luid)
		if err != nil {
			log.Fatal(err)
		}
		a := tokens.PrivilegeAttributeToString(v.Attributes)
		if a == "" {
			privileges = append(privileges, p)
		} else {
			privileges = append(privileges, fmt.Sprintf("%s (%s)", p, a))
		}
	}
	return
}

// ListPrivileges will enumerate the privileges associated with a Windows access token
// If the Process ID (pid) is 0, then the privileges for the token associated with current process will enumerated
func ListPrivileges(pid int) (string, error) {
	if pid == 0 {
		pid = os.Getpid()
	}

	// Get a handle to the current process

	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, true, uint32(pid))
	if err != nil {
		return "", fmt.Errorf("there was an error calling windows.OpenProcess(): %s", err)
	}

	// Close the handle when done
	defer func() {
		err := windows.CloseHandle(hProc)
		if err != nil {
			fmt.Printf("there was an error calling windows.CloseHandle() for the process: %s\n", err)
		}
	}()

	// Use process handle to get a token
	var token windows.Token
	err = windows.OpenProcessToken(hProc, windows.TOKEN_QUERY, &token)
	if err != nil {
		return "", fmt.Errorf("there was an error calling windows.OpenProcessToken(): %s", err)
	}

	// Close the handle when done
	defer func() {
		err := token.Close()
		if err != nil {
			fmt.Printf("there was an error calling token.Close(): %s\n", err)
		}
	}()

	// Call to get structure size
	var returnedLen uint32
	err = windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &returnedLen)
	if err != syscall.ERROR_INSUFFICIENT_BUFFER {
		return "", fmt.Errorf("there was an error calling windows.GetTokenInformation: %s", err)
	}

	// Call again to get the actual structure
	info := bytes.NewBuffer(make([]byte, returnedLen))
	err = windows.GetTokenInformation(token, windows.TokenPrivileges, &info.Bytes()[0], returnedLen, &returnedLen)
	if err != nil {
		return "", fmt.Errorf("there was an error calling windows.GetTokenInformation: %s", err)
	}

	var privilegeCount uint32
	err = binary.Read(info, binary.LittleEndian, &privilegeCount)
	if err != nil {
		return "", fmt.Errorf("there was an error reading TokenPrivileges bytes to privilegeCount: %s", err)
	}

	// Read in the LUID and Attributes
	var privs []windows.LUIDAndAttributes
	for i := 1; i <= int(privilegeCount); i++ {
		var priv windows.LUIDAndAttributes
		err = binary.Read(info, binary.LittleEndian, &priv)
		if err != nil {
			return "", fmt.Errorf("there was an error reading LUIDAttributes to bytes: %s", err)
		}
		privs = append(privs, priv)
	}

	var data string

	for _, v := range privs {
		var luid advapi32.LUID
		luid.HighPart = v.Luid.HighPart
		luid.LowPart = v.Luid.LowPart
		p, err := advapi32.LookupPrivilegeName(luid)
		if err != nil {
			log.Fatal(err)
		}
		data += fmt.Sprintf("[+] Privilege: %s, Attribute: %s\n", p, tokens.PrivilegeAttributeToString(v.Attributes))
	}
	return data, nil
}
