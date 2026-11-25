package protocol

// Kind is a stable error category shared by the SDK and the Manager.
type Kind int

const (
	Empty Kind = iota + 1
	BadCharacter
	Incomplete
	TooLong
	Typo
	UnsupportedFormat
	Malformed    // a file or message that is not a well-formed protocol object
	Untrusted    // no trusted root certified the signing key, or the key is distrusted
	BadSignature // the signature does not verify
	WrongProduct
	WrongDevice
)

var kindNames = map[Kind]string{
	Empty: "Empty", BadCharacter: "BadCharacter", Incomplete: "Incomplete", TooLong: "TooLong",
	Typo: "Typo", UnsupportedFormat: "UnsupportedFormat", Malformed: "Malformed", Untrusted: "Untrusted",
	BadSignature: "BadSignature", WrongProduct: "WrongProduct", WrongDevice: "WrongDevice",
}

func (k Kind) String() string {
	if s, ok := kindNames[k]; ok {
		return s
	}
	return "Unknown"
}

// Error describes why input was rejected. Group is the 1-based group of a
// bad character or typo (0 if unknown). Have and Want count groups for
// Incomplete.
type Error struct {
	Kind       Kind
	Group      int
	Have, Want int
}

func (e *Error) Error() string { return "protocol: " + e.Kind.String() }

func malformed() error { return &Error{Kind: Malformed} }
