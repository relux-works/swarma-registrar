package keys

import "math/big"

// These field constants follow the Ed25519 curve: p=2^255-19,
// -x²+y²=1+d*x²*y², d=-121665/121666, and the subgroup order L from §3.1.
// All arithmetic here is variable-time and operates on PUBLIC points only.
// Signing and the verification equation remain in crypto/ed25519.
var fieldPrime = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
var curveD = mod(new(big.Int).Mul(big.NewInt(-121665), new(big.Int).ModInverse(big.NewInt(121666), fieldPrime)))
var subgroupOrder = func() *big.Int {
	tail, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	return new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 252), tail)
}()

func mod(n *big.Int) *big.Int    { return new(big.Int).Mod(n, fieldPrime) }
func add(a, b *big.Int) *big.Int { return mod(new(big.Int).Add(a, b)) }
func sub(a, b *big.Int) *big.Int { return mod(new(big.Int).Sub(a, b)) }
func mul(a, b *big.Int) *big.Int { return mod(new(big.Int).Mul(a, b)) }
func littleInteger(raw []byte) *big.Int {
	b := make([]byte, len(raw))
	for i := range raw {
		b[len(raw)-1-i] = raw[i]
	}
	return new(big.Int).SetBytes(b)
}

// extendedPoint represents affine (X/Z,Y/Z), with T=XY/Z. Complete addition
// on this a=-1 twisted Edwards curve avoids per-step inversions.
type extendedPoint struct{ x, y, z, t *big.Int }

func identityPoint() extendedPoint {
	return extendedPoint{big.NewInt(0), big.NewInt(1), big.NewInt(1), big.NewInt(0)}
}
func pointAdd(p, q extendedPoint) extendedPoint {
	a := mul(sub(p.y, p.x), sub(q.y, q.x))
	b := mul(add(p.y, p.x), add(q.y, q.x))
	c := mul(add(curveD, curveD), mul(p.t, q.t))
	d := mul(big.NewInt(2), mul(p.z, q.z))
	e, f, g, h := sub(b, a), sub(d, c), add(d, c), add(b, a)
	return extendedPoint{mul(e, f), mul(g, h), mul(f, g), mul(e, h)}
}
func (p extendedPoint) identity() bool {
	return p.z.Sign() != 0 && p.x.Sign() == 0 && p.y.Cmp(p.z) == 0
}

// ValidEd25519Point enforces canonical decompression and a nonidentity point
// in the prime-order subgroup: [L]P=identity, rejecting small and mixed orders.
func ValidEd25519Point(raw []byte) bool {
	if len(raw) != 32 {
		return false
	}
	encoded := append([]byte(nil), raw...)
	sign := uint(encoded[31] >> 7)
	encoded[31] &= 127
	y := littleInteger(encoded)
	if y.Cmp(fieldPrime) >= 0 {
		return false
	}
	y2 := mul(y, y)
	denominator := add(mul(curveD, y2), big.NewInt(1))
	inverse := new(big.Int).ModInverse(denominator, fieldPrime)
	if inverse == nil {
		return false
	}
	x2 := mul(sub(y2, big.NewInt(1)), inverse)
	x := new(big.Int).ModSqrt(x2, fieldPrime)
	if x == nil {
		return false
	}
	if x.Sign() == 0 && sign == 1 {
		return false
	}
	if x.Bit(0) != sign {
		x.Sub(fieldPrime, x)
	}
	p := extendedPoint{x, y, big.NewInt(1), mul(x, y)}
	if p.identity() {
		return false
	}
	acc := identityPoint()
	for i := subgroupOrder.BitLen() - 1; i >= 0; i-- {
		acc = pointAdd(acc, acc)
		if subgroupOrder.Bit(i) == 1 {
			acc = pointAdd(acc, p)
		}
	}
	return acc.identity()
}
