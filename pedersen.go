package bulletproofs

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1"
)

// Commitment - this contains the details for each commitment
type Commitment struct {
	Comm ECPoint
	// encrypted values
	EncValue []byte
	Blind    *big.Int
}

/*
VectorPCommit - Vector Pedersen Commit

Given an array of values, we commit the array with different generators
for each element and for each randomness.
*/
func VectorPCommit(value []*big.Int) (ECPoint, []*big.Int) {
	R := make([]*big.Int, EC.V)

	commitment := EC.Zero()

	for i := 0; i < EC.V; i++ {
		r, err := rand.Int(rand.Reader, EC.N)
		check(err)

		R[i] = r

		modValue := new(big.Int).Mod(value[i], EC.N)

		// mG, rH
		lhsX, lhsY := EC.C.ScalarMult(EC.BPG[i].X, EC.BPG[i].Y, modValue.Bytes())
		rhsX, rhsY := EC.C.ScalarMult(EC.BPH[i].X, EC.BPH[i].Y, r.Bytes())

		commitment = commitment.Add(ECPoint{lhsX, lhsY}).Add(ECPoint{rhsX, rhsY})
	}

	return commitment, R
}

/*
TwoVectorPCommit - Two Vector P Commit

Given an array of values, we commit the array with different generators
for each element and for each randomness.
*/
func TwoVectorPCommit(a []*big.Int, b []*big.Int) ECPoint {
	if len(a) != len(b) {
		fmt.Println("TwoVectorPCommit: Uh oh! Arrays not of the same length")
		fmt.Printf("len(a): %d\n", len(a))
		fmt.Printf("len(b): %d\n", len(b))
	}

	commitment := EC.Zero()

	for i := 0; i < EC.V; i++ {
		commitment = commitment.Add(EC.BPG[i].Mult(a[i])).Add(EC.BPH[i].Mult(b[i]))
	}

	return commitment
}

/*
TwoVectorPCommitWithGens - Vector Pedersen Commitment with Gens

Given an array of values, we commit the array with different generators
for each element and for each randomness.

We also pass in the Generators we want to use
*/
func TwoVectorPCommitWithGens(G, H []ECPoint, a, b []*big.Int) ECPoint {
	if len(G) != len(H) || len(G) != len(a) || len(a) != len(b) {
		fmt.Println("TwoVectorPCommitWithGens: Uh oh! Arrays not of the same length")
		fmt.Printf("len(G): %d\n", len(G))
		fmt.Printf("len(H): %d\n", len(H))
		fmt.Printf("len(a): %d\n", len(a))
		fmt.Printf("len(b): %d\n", len(b))
	}

	commitment := EC.Zero()

	for i := 0; i < len(G); i++ {
		modA := new(big.Int).Mod(a[i], EC.N)
		modB := new(big.Int).Mod(b[i], EC.N)

		commitment = commitment.Add(G[i].Mult(modA)).Add(H[i].Mult(modB))
	}

	return commitment
}

/*
VectorPCommitTrans -Vector Pedersen Commit with Gens and BF
This modified method is to be used with input and output transactions
*/
func VectorPCommitTrans(pubkey *secp256k1.PublicKey, value []*big.Int, sSecret *big.Int) (ECPoint, []*big.Int, [][]byte) {
	R := make([]*big.Int, EC.V)

	commitment := EC.Zero()

	encValues := make([][]byte, EC.V)

	for i := 0; i < EC.V; i++ {
		hash := sha256.Sum256(value[i].Bytes())
		r := secp256k1.NonceRFC6979(sSecret, hash[:], nil, nil)

		R[i] = r

		// create the encrypted hash
		fmt.Printf("values are %s\n", value[i])
		ciphertext, err := secp256k1.Encrypt(pubkey, []byte(value[i].String()))
		check(err)

		encValues[i] = ciphertext

		modValue := new(big.Int).Mod(value[i], EC.N)

		// mG, rH
		lhsX, lhsY := EC.C.ScalarMult(EC.BPG[i].X, EC.BPG[i].Y, modValue.Bytes())
		rhsX, rhsY := EC.C.ScalarMult(EC.BPH[i].X, EC.BPH[i].Y, r.Bytes())

		commitment = commitment.Add(ECPoint{lhsX, lhsY}).Add(ECPoint{rhsX, rhsY})
	}

	return commitment, R, encValues
}
