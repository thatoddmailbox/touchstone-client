package touchstone

import "errors"

// ErrBadCreds is returned when the given credentials were invalid.
var ErrBadCreds = errors.New("touchstone: bad credentials")

// ErrBadParent is returned when the Duo response is for a different parent than Touchstone.
var ErrBadParent = errors.New("touchstone: bad parent in Duo response")

// ErrServer is returned when there's an unexpected error with the Touchstone servers.
var ErrServer = errors.New("touchstone: server error")

// ErrUnknownResponse is returned when Touchstone gives a response that couldn't be handled.
var ErrUnknownResponse = errors.New("touchstone: unknown response")
