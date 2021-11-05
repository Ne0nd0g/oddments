# HideConsole

This program will use the Windows API to hide the program's window so that it isn't visible.

## Usage

```text
  -debug
        Enable debug output
  -foreground
        Hide the foreground window (e.g., windowsterminal.exe)
  -sleep int
        Amount of time to sleep before hiding the window (default 10)
  -verbose
        Enable verbose output
```

## WIN API

The following Windows API calls are used:

- [GetConsoleWindow](https://docs.microsoft.com/en-us/windows/console/getconsolewindow)
    - Get a handle to the console window
- [GetForegroundWindow](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getforegroundwindow)
  - Get a handle to the foreground window. Useful when calling this program from another like `windowsterminal.exe`
- [ShowWindow](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-showwindow)
    - Hide the window using the `SW_HIDE` constant
