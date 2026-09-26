package probe

import "golang.org/x/sys/windows"

// Winsock reports WSA* codes, which differ from the syscall.E* constants.
var (
	refusedErrors     = []error{windows.WSAECONNREFUSED}
	unreachableErrors = []error{windows.WSAENETUNREACH, windows.WSAEHOSTUNREACH}
)
