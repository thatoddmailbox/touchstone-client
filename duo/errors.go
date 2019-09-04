package duo

import "errors"

// ErrMethodNotSupported is returned when an attempt is made to use a Method that is currently not supported.
var ErrMethodNotSupported = errors.New("duo: method not supported")

// ErrDuoServer is returned when an error is returned by the Duo servers for an unknown reason.
var ErrDuoServer = errors.New("duo: server error")
