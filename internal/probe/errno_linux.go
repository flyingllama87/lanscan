package probe

import "syscall"

var (
	refusedErrors     = []error{syscall.ECONNREFUSED}
	unreachableErrors = []error{syscall.ENETUNREACH, syscall.EHOSTUNREACH}
)
