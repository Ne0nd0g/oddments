package user32

import (
	// Standard
	"fmt"
	"syscall"
	"unsafe"

	// X Packages
	"golang.org/x/sys/windows"
)

var User32 = windows.NewLazySystemDLL("User32.dll")

// STARTF A bitfield that determines whether certain STARTUPINFO members are used when the process creates a window.
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfow
const (
	STARTF_USESHOWWINDOW uint32 = 0x00000001 // The wShowWindow member contains additional information.
)

// SW Show Window controls how the window is to be shown.
// This parameter is ignored the first time an application calls ShowWindow, if the program that launched the
// application provides a STARTUPINFO structure. Otherwise, the first time ShowWindow is called, the value should be
// the value obtained by the WinMain function in its nCmdShow parameter.
// https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-showwindow
const (
	SW_HIDE            int = iota // Hides the window and activates another window.
	SW_SHOWNORMAL                 // Activates and displays a window. If the window is minimized or maximized, the system restores it to its original size and position. An application should specify this flag when displaying the window for the first time.
	SW_SHOWMINIMIZED              // Activates the window and displays it as a minimized window.
	SW_SHOWMAXIMIZED              // Activates the window and displays it as a maximized window.
	SW_SHOWNOACTIVATE             // Displays a window in its most recent size and position. This value is similar to SW_SHOWNORMAL, except that the window is not activated.
	SW_SHOW                       // Activates the window and displays it in its current size and position.
	SW_MINIMIZE                   // Minimizes the specified window and activates the next top-level window in the Z order.
	SW_SHOWMINNOACTIVE            // Displays the window as a minimized window. This value is similar to SW_SHOWMINIMIZED, except the window is not activated.
	SW_SHOWNA                     // Displays the window in its current size and position. This value is similar to SW_SHOW, except that the window is not activated.
	SW_RESTORE                    // Activates and displays the window. If the window is minimized or maximized, the system restores it to its original size and position. An application should specify this flag when restoring a minimized window.
	SW_SHOWDEFAULT                // Sets the show state based on the SW_ value specified in the STARTUPINFO structure passed to the CreateProcess function by the program that started the application.
	SW_FORCEMINIMIZE              // Minimizes a window, even if the thread that owns the window is not responding. This flag should only be used when minimizing windows from a different thread.
)

// ShowWindowN Sets the specified window's show state.
// The "N" in the function name is for Native as it avoids using external packages
// https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-showwindow
func ShowWindowN(handle *unsafe.Pointer, CmdShow int) (visible bool, err error) {
	ShowWindow := User32.NewProc("ShowWindow")
	// BOOL ShowWindow(
	//  [in] HWND hWnd,
	//  [in] int  nCmdShow
	//);
	shown, _, err := ShowWindow.Call(uintptr(*handle), uintptr(CmdShow))
	if err != syscall.Errno(0) {
		err = fmt.Errorf("there was an error calling user32!ShowWindow: %s", err)
		return
	}
	err = nil
	// If the window was previously visible, the return value is nonzero.
	//If the window was previously hidden, the return value is zero.
	if shown == 1 {
		visible = true
	}
	return
}

// GetParentN Retrieves a handle to the specified window's parent or owner.
// https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getparent
func GetParentN(handle *unsafe.Pointer) (hParentWnd *unsafe.Pointer, err error) {
	GetParent := User32.NewProc("GetParent")

	// HWND GetParent(
	//  [in] HWND hWnd
	//);
	hWnd, _, err := GetParent.Call(uintptr(*handle))
	if err != syscall.Errno(0) {
		err = fmt.Errorf("there was an error calling user32!GetParent: %s", err)
		return
	}

	// I believe this misuse of unsafe.Pointer is required because the Windows API call returns a uintptr which could be garbage collected
	h := unsafe.Pointer(hWnd)
	return &h, nil
}

// GetForegroundWindowN Retrieves a handle to the foreground window (the window with which the user is currently working).
// The system assigns a slightly higher priority to the thread that creates the foreground window than it does to other threads.
// https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getforegroundwindow
func GetForegroundWindowN() (hwnd *unsafe.Pointer, err error) {
	GetForegroundWindow := User32.NewProc("GetForegroundWindow")
	// HWND GetForegroundWindow();

	handle, _, err := GetForegroundWindow.Call()
	if err != syscall.Errno(0) {
		err = fmt.Errorf("there was an error calling user32!GetForegroundWindow: %s", err)
		return
	}
	err = nil
	// I believe this misuse of unsafe.Pointer is required because the Windows API call returns a uintptr which could be garbage collected
	h := unsafe.Pointer(handle)
	return &h, err
}

// GetActiveWindowN Retrieves the window handle to the active window attached to the calling thread's message queue.
// https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getactivewindow
func GetActiveWindowN() (hwnd *unsafe.Pointer, err error) {
	GetActiveWindow := User32.NewProc("GetActiveWindow")
	// HWND GetActiveWindow();

	handle, _, err := GetActiveWindow.Call()
	if err != syscall.Errno(0) {
		err = fmt.Errorf("there was an error calling user32!GetActiveWindow: %s", err)
		return
	}
	err = nil
	// I believe this misuse of unsafe.Pointer is required because the Windows API call returns a uintptr which could be garbage collected
	h := unsafe.Pointer(handle)
	return &h, err
}
