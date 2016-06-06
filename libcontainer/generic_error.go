package libcontainer

import (
	"encoding/json"
	"fmt"
	"io"
	"text/template"
	"time"

	"github.com/opencontainers/runc/libcontainer/stacktrace"
	"github.com/opencontainers/runc/libcontainer/utils"
)

type syncType uint8

// Constants that are used for synchronisation between the parent and child
// during container setup. They come in pairs (with procError being a generic
// response which is followed by a &genericError).
//
// [  child  ] <-> [   parent   ]
//
// procConsole --> [create console fd]
//             <-- procFd [with sendmsg(fd)]
//
// procHooks   --> [run hooks]
//             <-- procResume
//
// procReady   --> [final setup]
//             <-- procRun
const (
	procError syncType = iota
	procReady
	procRun
	procHooks
	procResume
	procConsole
	procFd
)

type syncT struct {
	Type syncType `json:"type"`
}

// Used to write to a synchronisation pipe. An error is returned if there was
// a problem writing the payload.
func writeSync(pipe io.Writer, sync syncType) error {
	if err := utils.WriteJSON(pipe, syncT{sync}); err != nil {
		return err
	}
	return nil
}

// Used to read from a synchronisation pipe. An error is returned if we got a
// genericError, the pipe was closed, or we got an unexpected flag.
func readSync(pipe io.Reader, expected syncType) error {
	var procSync syncT
	if err := json.NewDecoder(pipe).Decode(&procSync); err != nil {
		if err == io.EOF {
			return fmt.Errorf("parent closed synchronisation channel")
		}

		if procSync.Type == procError {
			var ierr genericError

			if err := json.NewDecoder(pipe).Decode(&ierr); err != nil {
				return fmt.Errorf("failed reading error from parent: %v", err)
			}

			return &ierr
		}

		if procSync.Type != expected {
			return fmt.Errorf("invalid synchronisation flag from parent")
		}
	}
	return nil
}

var errorTemplate = template.Must(template.New("error").Parse(`Timestamp: {{.Timestamp}}
Code: {{.ECode}}
{{if .Message }}
Message: {{.Message}}
{{end}}
Frames:{{range $i, $frame := .Stack.Frames}}
---
{{$i}}: {{$frame.Function}}
Package: {{$frame.Package}}
File: {{$frame.File}}@{{$frame.Line}}{{end}}
`))

func newGenericError(err error, c ErrorCode) Error {
	if le, ok := err.(Error); ok {
		return le
	}
	gerr := &genericError{
		Timestamp: time.Now(),
		Err:       err,
		ECode:     c,
		Stack:     stacktrace.Capture(1),
	}
	if err != nil {
		gerr.Message = err.Error()
	}
	return gerr
}

func newSystemError(err error) Error {
	return createSystemError(err, "")
}

func newSystemErrorWithCausef(err error, cause string, v ...interface{}) Error {
	return createSystemError(err, fmt.Sprintf(cause, v...))
}

func newSystemErrorWithCause(err error, cause string) Error {
	return createSystemError(err, cause)
}

// createSystemError creates the specified error with the correct number of
// stack frames skipped. This is only to be called by the other functions for
// formatting the error.
func createSystemError(err error, cause string) Error {
	if le, ok := err.(Error); ok {
		return le
	}
	gerr := &genericError{
		Timestamp: time.Now(),
		Err:       err,
		ECode:     SystemError,
		Cause:     cause,
		Stack:     stacktrace.Capture(2),
	}
	if err != nil {
		gerr.Message = err.Error()
	}
	return gerr
}

type genericError struct {
	Timestamp time.Time
	ECode     ErrorCode
	Err       error `json:"-"`
	Cause     string
	Message   string
	Stack     stacktrace.Stacktrace
}

func (e *genericError) Error() string {
	if e.Cause == "" {
		return e.Message
	}
	frame := e.Stack.Frames[0]
	return fmt.Sprintf("%s:%d: %s caused %q", frame.File, frame.Line, e.Cause, e.Message)
}

func (e *genericError) Code() ErrorCode {
	return e.ECode
}

func (e *genericError) Detail(w io.Writer) error {
	return errorTemplate.Execute(w, e)
}
