package licensekit

import "fmt"

// messages are the default customer-safe English texts for each error kind.
var messages = map[Kind]string{
	Empty:             "Enter your license key or renewal code, or open your license file.",
	BadCharacter:      "The code contains a character that isn't used in codes.",
	Incomplete:        "The code looks incomplete.",
	TooLong:           "The code is longer than expected. Enter only the code.",
	Typo:              "There's a typo in the code. Please check it.",
	UnsupportedFormat: "This code or file needs a newer version of the app. Please update.",
	WrongKind:         "This is a license request file. Send it to us, and open the license file we send back.",
	InvalidLicense:    "This license file isn't valid for this app.",
	OtherComputer:     "This license is for a different computer. Activate this computer with your license key.",
	WrongRenewal:      "This renewal code is for a different computer or license.",
	NeedsActivation:   "Activate the app with your license key first, then enter the renewal code.",
	AlreadyApplied:    "This renewal code is already applied.",
	AlreadyExpired:    "This license or renewal has already ended. Contact us to renew.",
	ClockWrong:        "Your computer's date or time appears to be wrong. Correct it and try again.",
	StorageFailed:     "The license couldn't be saved on this computer. Check that the app can write to its data folder.",
	NeedsOnline:       "Activating with a license key needs an internet connection. Without one, save a request file and send it to us.",

	Offline:           "The activation server couldn't be reached. Check the internet connection and try again, or save a request file and send it to us.",
	KeyNotValid:       "This license key isn't valid for this app. Check the key and try again.",
	KeyInUse:          "This license key is in use on another computer. Deactivate it there first, or contact us.",
	MovesExhausted:    "This license key has moved between computers too often. Contact us to move it again.",
	LicenseExpired:    "This license has expired. Contact us to renew it.",
	LicenseCanceled:   "This license was canceled. Contact us for help.",
	NotDeactivatable:  "This computer has no license it can give back online.",
	RateLimited:       "Too many attempts. Wait a few minutes and try again.",
	ServerUnavailable: "The activation server is temporarily unavailable. Try again later, or save a request file and send it to us.",

	NotConfigured:     "This build of the app has no licensing configuration. Contact the vendor for a corrected build.",
	BadProduct:        "This build of the app has an invalid product name. Contact the vendor for a corrected build.",
	DeviceUnavailable: "This computer doesn't provide a stable identifier, so the app can't be activated here. Contact the vendor.",
}

func stateMessage(s Status) string {
	const date = "2 Jan 2006"
	switch s.State {
	case Active:
		if s.Perpetual {
			return "Licensed (no expiry)."
		}
		return fmt.Sprintf("Licensed through %s.", s.Expires.Format(date))
	case Expired:
		return fmt.Sprintf("Your license ended on %s. Enter a renewal code to continue.", s.Expires.Format(date))
	case WrongDevice:
		return "The saved license belongs to a different computer. Activate this computer with your license key."
	case ClockProblem:
		return "Your computer's date or time appears to be wrong. Correct it to continue."
	case Invalid:
		return "The saved license is no longer accepted by this version. Activate again with your license key."
	}
	return "This copy isn't activated yet. Enter your license key to activate it."
}
