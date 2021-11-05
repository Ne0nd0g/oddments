// +build windows

package main

import (
	"flag"
	"fmt"
	"log"
	"oddments/windows/kernel32"
	"oddments/windows/user32"
	"os"
	"time"
)

var verbose bool
var debug bool

func main() {
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output")
	flag.BoolVar(&debug, "debug", false, "Enable debug output")
	var foreground = flag.Bool("foreground", false, "Hide the foreground window (e.g., windowsterminal.exe)")
	var sleep = flag.Int("sleep", 10, "Amount of time to sleep before hiding the window")
	flag.Usage = func() {
		flag.PrintDefaults()
		os.Exit(0)
	}
	flag.Parse()

	if debug {
		fmt.Println("[DEBUG] Calling GetConsoleWindowN...")
	}
	handle, err := kernel32.GetConsoleWindowN()
	if err != nil {
		log.Fatal(err)
	}
	if verbose {
		fmt.Printf("[-] Got console window handle: 0x%X\n", *handle)
	}

	if *foreground {
		if debug {
			fmt.Println("[DEBUG] Calling GetForegroundWindow...")
		}
		hParent, err := user32.GetForegroundWindowN()
		if err != nil {
			log.Fatal(err)
		}
		if verbose {
			fmt.Printf("[-] Got handle to foreground window: 0x%X\n", *hParent)
		}

		fmt.Printf("[-] Sleeping for %d seconds before hiding the parent window...\n", *sleep)
		time.Sleep(time.Duration(*sleep) * time.Second)

		if debug {
			fmt.Println("[DEBUG] Calling ShowWindow to hid the parent (foreground) window...")
		}
		shown, err := user32.ShowWindowN(hParent, user32.SW_HIDE)
		if err != nil {
			log.Fatal(err)
		}
		if verbose {
			// Shouldn't be able to see this
			fmt.Printf("[-] Successfully called ShowWindow which returned: %t\n", shown)
		}
		fmt.Printf("[-] Sleeping for another %d seconds, but you shouldn't see this message...\n", *sleep)
		time.Sleep(time.Duration(*sleep) * time.Second)
	} else {
		fmt.Printf("[-] Sleeping for %d seconds before hiding the program window...\n", *sleep)
		time.Sleep(time.Duration(*sleep) * time.Second)

		if debug {
			fmt.Println("[DEBUG] Calling ShowWindow to hide this Go program...")
		}
		// Not sure why, but this will hide the window if you double-click the program or run it from cmd.exe/powershell.exe
		// However, it will not hide the window if you run it from windowsterminal.exe, the -parent flag must be used
		shown, err := user32.ShowWindowN(handle, user32.SW_HIDE)
		if err != nil {
			log.Fatal(err)
		}
		if verbose {
			// Shouldn't be able to see this
			fmt.Printf("[-] Successfully called ShowWindow which returned: %t\n", shown)
		}

		fmt.Printf("[-] Sleeping for another %d seconds, but you shouldn't see this message...\n", *sleep)
		fmt.Println("[-] If you do, you might have run this Go program from another program like windowsterminal.exe")
		fmt.Println("[-] Use the -foreground argument to hide the calling program's window too")
		time.Sleep(time.Duration(*sleep) * time.Second)
	}
}
