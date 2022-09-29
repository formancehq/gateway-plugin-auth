package gateway_plugin_auth

import (
	"fmt"
)

type errorType string

type Error struct {
	Parent           error     `json:"-" schema:"-"`
	ErrorType        errorType `json:"error" schema:"error"`
	Description      string    `json:"error_description,omitempty" schema:"error_description,omitempty"`
	State            string    `json:"state,omitempty" schema:"state,omitempty"`
	redirectDisabled bool      `schema:"-"`
}

func (e *Error) Error() string {
	message := "ErrorType=" + string(e.ErrorType)
	if e.Description != "" {
		message += " Description=" + e.Description
	}
	if e.Parent != nil {
		message += " Parent=" + e.Parent.Error()
	}
	return message
}

func (e *Error) Unwrap() error {
	return e.Parent
}

func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return e.ErrorType == t.ErrorType &&
		(e.Description == t.Description || t.Description == "") &&
		(e.State == t.State || t.State == "")
}

func (e *Error) WithParent(err error) *Error {
	e.Parent = err
	return e
}

func (e *Error) WithDescription(desc string, args ...interface{}) *Error {
	e.Description = fmt.Sprintf(desc, args...)
	return e
}

func (e *Error) IsRedirectDisabled() bool {
	return e.redirectDisabled
}
