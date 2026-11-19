package crypto

import "fmt"

// securityStrengther is implemented by the key pair generators in this
// package. Each generator reports the security strength of the keys it
// generates, so adding a key algorithm means implementing securityBits on
// its generator rather than updating a central switch.
//
// The strength is the classical NIST security strength in bits. When a
// post-quantum algorithm such as ML-DSA is added, a single classical number
// no longer orders keys correctly: classical RSA and ECDSA keys provide
// effectively no security against a quantum adversary, so any post-quantum
// key must outrank any classical key regardless of classical strength (for
// example ML-DSA-44 over ECDSA P-384), while classical keys keep their
// relative order among themselves. At that point securityBits must grow into
// a strength compared on post-quantum strength first and classical strength
// second. The interface is unexported so that its shape can change then
// without affecting callers.
type securityStrengther interface {
	securityBits() int
}

// StrongerKeyPairGenerator returns whichever of a or b provides the higher
// security strength. On a tie, ECDSA is preferred over RSA, and otherwise a
// is returned. Generators not created by this package are an error, so that
// callers fail closed instead of silently picking the weaker key.
func StrongerKeyPairGenerator(a, b KeyPairGenerator) (KeyPairGenerator, error) {
	sa, ok := a.(securityStrengther)
	if !ok {
		return nil, fmt.Errorf("cannot determine security strength of key generator %T", a)
	}
	sb, ok := b.(securityStrengther)
	if !ok {
		return nil, fmt.Errorf("cannot determine security strength of key generator %T", b)
	}
	if sb.securityBits() > sa.securityBits() {
		return b, nil
	}
	if sa.securityBits() > sb.securityBits() {
		return a, nil
	}
	// Equal strength: prefer ECDSA over RSA.
	if _, ok := a.(ecdsaKeyPairGenerator); ok {
		return a, nil
	}
	if _, ok := b.(ecdsaKeyPairGenerator); ok {
		return b, nil
	}
	return a, nil
}

// rsaSecurityStrength lists RSA key sizes in ascending order with their
// security strengths from NIST SP 800-56B Rev 2 Table 2 or pre-calculated
// from the GNFS complexity estimate.
var rsaSecurityStrength = []struct {
	bits, strength int
}{
	{bits: 2048, strength: 112},
	{bits: 3072, strength: 128},
	{bits: 4096, strength: 152},
	{bits: 5120, strength: 168},
	{bits: 6144, strength: 176},
	{bits: 7168, strength: 192},
	{bits: 8192, strength: 200},
}

// securityBits returns the strength of the largest tabulated RSA key size not
// exceeding the generator's size. Rounding down keeps the estimate
// conservative for sizes between table entries and caps it at the largest
// entry. A size below the table, which the constructor rejects, has strength
// 0 and loses every comparison; its GenerateKeyPair fails regardless.
func (g rsaKeyPairGenerator) securityBits() int {
	strength := 0
	for _, e := range rsaSecurityStrength {
		if e.bits > g.bits {
			break
		}
		strength = e.strength
	}
	return strength
}

// securityBits returns half the curve's key size, the security strength of
// ECDSA. An unknown curve, which the constructor rejects, has strength 0.
func (g ecdsaKeyPairGenerator) securityBits() int {
	switch g.curve {
	case P256:
		return 128
	case P384:
		return 192
	case P521:
		return 256
	default:
		return 0
	}
}
