package licensekit

import (
	"errors"
	"fmt"

	"github.com/aqobadi/licensekit/protocol"
)

// Kind is a stable error category. Switch on it to localize messages.
type Kind int

const (
	Empty Kind = iota + 1
	BadCharacter
	Incomplete
	TooLong
	Typo
	UnsupportedFormat // a code or file from a newer version
	WrongKind         // a request file was pasted
	InvalidLicense    // not a valid license for this app
	OtherComputer     // a license for another computer
	WrongRenewal      // a renewal code for another computer or license
	NeedsActivation   // a renewal code before any license is installed
	AlreadyApplied    // the renewal code changes nothing
	AlreadyExpired
	ClockWrong
	StorageFailed
	NeedsOnline // a license key was entered where only offline input is possible

	// Online activation (package licensekit/online).
	Offline          // the activation server could not be reached
	KeyNotValid      // the license key is unknown or for another app
	KeyInUse         // the key is set up on another computer
	MovesExhausted   // the key moved computers too often
	LicenseExpired   // renew before setting up
	LicenseCanceled  // the vendor canceled the license
	NotDeactivatable // this computer holds no license it can give back
	RateLimited
	ServerUnavailable

	// Open only: developer or environment errors.
	NotConfigured     // the build has no licensing configuration
	BadProduct        // the product slug is invalid
	DeviceUnavailable // no usable OS identity; set Options.DeviceID
)

var kindNames = [...]string{"", "Empty", "BadCharacter", "Incomplete", "TooLong", "Typo", "UnsupportedFormat", "WrongKind",
	"InvalidLicense", "OtherComputer", "WrongRenewal", "NeedsActivation", "AlreadyApplied", "AlreadyExpired", "ClockWrong",
	"StorageFailed", "NeedsOnline", "Offline", "KeyNotValid", "KeyInUse", "MovesExhausted", "LicenseExpired",
	"LicenseCanceled", "NotDeactivatable", "RateLimited", "ServerUnavailable", "NotConfigured", "BadProduct",
	"DeviceUnavailable"}

func (k Kind) String() string {
	if k > 0 && int(k) < len(kindNames) {
		return kindNames[k]
	}
	return "Unknown"
}

// Error is returned by Open, Apply, RequestFile and the online calls.
// Message is safe to show to customers; Group is the 1-based group of a bad
// character or typo (0 if unknown).
type Error struct {
	Kind    Kind
	Group   int
	Message string
	err     error
}

func (e *Error) Error() string {
	if e.err != nil {
		return fmt.Sprintf("licensekit: %s: %v", e.Kind, e.err)
	}
	return "licensekit: " + e.Kind.String()
}

func (e *Error) Unwrap() error { return e.err }

// NewError returns an *Error with the default message for k. The SDK's
// network packages use it; applications rarely need to.
func NewError(k Kind, cause error) *Error { return &Error{Kind: k, Message: messages[k], err: cause} }

func newError(k Kind) *Error { return NewError(k, nil) }

// fromProtocol maps a protocol error from parsing a typed code or a license.
func fromProtocol(err error) *Error {
	var pe *protocol.Error
	if !errors.As(err, &pe) {
		return NewError(InvalidLicense, err)
	}
	k := map[protocol.Kind]Kind{
		protocol.Empty: Empty, protocol.BadCharacter: BadCharacter, protocol.Incomplete: Incomplete,
		protocol.TooLong: TooLong, protocol.Typo: Typo, protocol.UnsupportedFormat: UnsupportedFormat,
		protocol.WrongDevice: OtherComputer,
	}[pe.Kind]
	if k == 0 {
		k = InvalidLicense
	}
	e := NewError(k, err)
	e.Group = pe.Group
	switch {
	case k == Incomplete:
		e.Message = fmt.Sprintf("The code looks incomplete (%d of %d groups).", pe.Have, pe.Want)
	case k == BadCharacter && pe.Group > 0:
		e.Message = fmt.Sprintf("Group %d contains a character that isn't used in codes.", pe.Group)
	case k == Typo && pe.Group > 0:
		e.Message = fmt.Sprintf("There's a typo in group %d. Please check it.", pe.Group)
	}
	return e
}
