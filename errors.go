package tzsp

import "errors"

// Errors
var (
	ErrDataIsEmpty                 = errors.New("data is empty")
	ErrDataIsTooShort              = errors.New("data is too short")
	ErrUnknownHeaderVersion        = errors.New("unknown header version")
	ErrUnknownHeaderType           = errors.New("unknown header type")
	ErrUnknownFieldType            = errors.New("unknown field type")
	ErrUnknownEncapsulatedProtocol = errors.New("unknown encapsulated protocol")
)
