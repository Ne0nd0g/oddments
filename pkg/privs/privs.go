// +build windows

// Package privs contains wrapper functions that interact with Windows Access Tokens
// Many of the functions are used to enumerate privs and return them as a string

package privs

import (
	// Standard
	"encoding/binary"
	"fmt"
	"log"
	"unsafe"

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
