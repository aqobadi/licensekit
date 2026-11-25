package protocol

import "crypto/sha256"

// ChainDays is the renewal horizon of a new license: 50 years of daily
// steps (spec §7).
const ChainDays = 18262

// ChainValue is one 80-bit value of a renewal chain.
type ChainValue [10]byte

// ChainContext binds a chain to one product, computer and license.
type ChainContext struct {
	ProductID   [16]byte
	Fingerprint [15]byte
	LicenseID   uint32
}

// ChainLength returns the number of daily steps for a chain starting on
// base: ChainDays, shortened so base + length stays a valid day number.
func ChainLength(base uint16) uint16 {
	if room := 65535 - int(base); room < ChainDays {
		return uint16(room)
	}
	return ChainDays
}

// step computes x_(i-1) from x_i.
func (c ChainContext) step(i uint16, x ChainValue) ChainValue {
	h := sha256.New()
	h.Write([]byte("ZURVAN/RENEW/1\x00"))
	h.Write(c.ProductID[:])
	h.Write(c.Fingerprint[:])
	h.Write([]byte{byte(c.LicenseID >> 16), byte(c.LicenseID >> 8), byte(c.LicenseID), byte(i >> 8), byte(i)})
	h.Write(x[:])
	var out ChainValue
	copy(out[:], h.Sum(nil))
	return out
}

// Value returns x_k of the chain with the given seed and length n
// (Manager side). k must be at most n.
func (c ChainContext) Value(seed [32]byte, n, k uint16) ChainValue {
	var x ChainValue
	h := sha256.Sum256(append([]byte("ZURVAN/RENEW-SEED/1\x00"), seed[:]...))
	copy(x[:], h[:])
	for i := n; i > k; i-- {
		x = c.step(i, x)
	}
	return x
}

// Lock returns x_0, the value signed into the license.
func (c ChainContext) Lock(seed [32]byte, n uint16) ChainValue { return c.Value(seed, n, 0) }

// Check reports whether x is the chain value for step k of a chain whose
// lock is lock and whose length is n (device side, spec §7.2).
func (c ChainContext) Check(lock ChainValue, n, k uint16, x ChainValue) bool {
	if k == 0 || k > n {
		return false
	}
	for i := k; i > 0; i-- {
		x = c.step(i, x)
	}
	return x == lock
}
