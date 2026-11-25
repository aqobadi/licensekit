package protocol

// The activation API (spec §10): JSON over HTTPS, POST only. []byte fields
// are Base64 in JSON.
const (
	PathChallenge = "/api/v1/challenge"
	PathSetup     = "/api/v1/setup"
	PathRelease   = "/api/v1/deactivate"
	MaxAPIBody    = 8 << 10
)

// ChallengeResponse carries a single-use nonce. When Work is above zero the
// client must find a Counter with WorkBits(Nonce, Counter) >= Work.
type ChallengeResponse struct {
	Nonce []byte `json:"nonce"`
	Work  int    `json:"work"`
}

// SetupRequest asks for a license. Request is a signed Request whose Nonce
// is the challenge nonce and whose KeyHash is the hash of LicenseKey.
type SetupRequest struct {
	LicenseKey string `json:"license_key"`
	Request    []byte `json:"request"`
	Counter    uint64 `json:"counter"`
}

// SetupResponse carries the signed license.
type SetupResponse struct {
	License []byte `json:"license"`
}

// ReleaseRequest frees a seat. Release is a signed Release whose Nonce is
// the challenge nonce.
type ReleaseRequest struct {
	Release []byte `json:"release"`
	Counter uint64 `json:"counter"`
}

// ReleaseResponse carries the signed receipt.
type ReleaseResponse struct {
	Receipt []byte `json:"receipt"`
}

// APIError is the body of every non-200 response.
type APIError struct {
	Code    string `json:"error"`
	Message string `json:"message"`
}

// API error codes. The same "invalid_key" covers an unknown key, a key for
// another product and a malformed request, so the API never says which.
const (
	ErrInvalidKey     = "invalid_key"
	ErrInUse          = "in_use"           // the key is set up on another computer
	ErrMovesExhausted = "moves_exhausted"  // too many computers in 12 months
	ErrExpired        = "license_expired"  // renew first
	ErrCanceled       = "license_canceled" // the vendor canceled the license
	ErrNotSetUp       = "not_set_up"       // deactivate: this computer holds no seat
	ErrChallenge      = "bad_challenge"    // unknown, used or expired nonce, or too little work
	ErrRateLimited    = "rate_limited"
	ErrUnavailable    = "unavailable" // the Manager cannot sign right now
	ErrBadRequest     = "bad_request"
)
