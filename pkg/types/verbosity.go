package types

type Verbosity int

const (
	VerbositySilent Verbosity = iota
	VerbosityDefault
	VerbosityVerbose
	VerbosityVeryVerbose
)
