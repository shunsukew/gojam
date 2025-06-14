package workreport

import "github.com/pkg/errors"

var (
	ErrInvalidAssuance = errors.New("invalid assurance")

	ErrInvalidGuarantee  = errors.New("invalid guarantee")
	ErrInvalidCredential = errors.New("invalid credential")

	ErrTooManyGuarantees = errors.New("too many guarantees, must be less than or equal to number of cores")
	ErrInvalidGuarantees = errors.New("invalid guarantees")

	ErrInvalidWorkReport = errors.New("invalid work report")
)
