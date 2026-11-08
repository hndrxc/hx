package secret

import "errors"

var (
	ErrDestroyed          = errors.New("secret: value destroyed or uninitialized")
	ErrEmpty              = errors.New("secret: empty value")
	ErrTooLarge           = errors.New("secret: value exceeds maximum size")
	ErrIngestionForbidden = errors.New("secret: decoding secrets from text, configuration or flags is forbidden")

	ErrInvalidIntegration = errors.New("secret: invalid integration identifier")
	ErrInvalidScope       = errors.New("secret: invalid scope")
	ErrNoScopes           = errors.New("secret: handle requires at least one scope")
	ErrNoSource           = errors.New("secret: handle requires a source")
	ErrScopeNotDeclared   = errors.New("secret: scope not declared for integration")
	ErrNotFound           = errors.New("secret: not found")
	ErrLocked             = errors.New("secret: vault locked")

	ErrNotTerminal  = errors.New("secret: interactive input requires a terminal")
	ErrInvalidLabel = errors.New("secret: invalid prompt label")
)
