package bp_go

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"fmt"
	"math"
	"strconv"

	"github.com/decred/dcrd/dcrec/secp256k1"
	"errors"
)

// EC - An instance of CryptoParams
var EC CryptoParams

// VecLength - the length of the vector
var VecLength = 64

func VerifyTrans(key int, x, y *big.Int, proof string) (bool, error) {
	EC = NewECPrimeGroupKey(key)
	comm := ECPoint{x, y}
	rangeProof := RangeProof{}
	err := rangeProof.Rebuild(proof)
	if err != nil {
		return false, err
	}
	valid := RPVerifyTrans(&comm, &rangeProof)

	if !valid {
		err := errors.New("The range proof failed to verify")
		return false, err
	}

	return valid, nil
}

// ECPoint - an elliptic curve point
type ECPoint struct {
	X, Y *big.Int
}

// Equal returns true if points p (self) and p2 (arg) are the same.
func (p ECPoint) Equal(p2 ECPoint) bool {
	if p.X.Cmp(p2.X) == 0 && p2.Y.Cmp(p2.Y) == 0 {
		return true
	}
	return false
}

// Mult multiplies point p by scalar s and returns the resulting point
func (p ECPoint) Mult(s *big.Int) ECPoint {
	modS := new(big.Int).Mod(s, EC.N)
	X, Y := EC.C.ScalarMult(p.X, p.Y, modS.Bytes())
	return ECPoint{X, Y}
}

// Add adds points p and p2 and returns the resulting point
func (p ECPoint) Add(p2 ECPoint) ECPoint {
	X, Y := EC.C.Add(p.X, p.Y, p2.X, p2.Y)
	return ECPoint{X, Y}
}

// Neg returns the additive inverse of point p
func (p ECPoint) Neg() ECPoint {
	negY := new(big.Int).Neg(p.Y)
	modValue := negY.Mod(negY, EC.C.Params().P) // mod P is fine here because we're describing a curve point
	return ECPoint{p.X, modValue}
}

func (p ECPoint) Bytes() []byte {
	key := secp256k1.NewPublicKey(p.X, p.Y)
	return key.SerializeCompressed()
}

func (p *ECPoint) Rebuild(buf []byte) error {
	key, err := secp256k1.ParsePubKey(buf)
	if err != nil {
		return err
	}
	p.X = key.X
	p.Y = key.Y
	return nil
}

// CryptoParams - the struct containing the crypto params for the rangeproofs
type CryptoParams struct {
	C   elliptic.Curve      // curve
	KC  *secp256k1.KoblitzCurve // curve
	BPG []ECPoint           // slice of gen 1 for BP
	BPH []ECPoint           // slice of gen 2 for BP
	N   *big.Int            // scalar prime
	U   ECPoint             // a point that is a fixed group element with an unknown discrete-log relative to g,h
	V   int                 // Vector length
	G   ECPoint             // G value for commitments of a single value
	H   ECPoint             // H value for commitments of a single value
}

// Zero - returns a Zero ECPoint
func (c CryptoParams) Zero() ECPoint {
	return ECPoint{big.NewInt(0), big.NewInt(0)}
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

// InnerProdArg - Stores the values of the InnerProduct Arguements
type InnerProdArg struct {
	L []ECPoint
	R []ECPoint
	A *big.Int
	B *big.Int

	Challenges []*big.Int
}

// GenerateNewParams - Creates new EC Parameters to be used in the bulletproofs
func GenerateNewParams(G, H []ECPoint, x *big.Int, L, R, P ECPoint) ([]ECPoint, []ECPoint, ECPoint) {
	nprime := len(G) / 2

	Gprime := make([]ECPoint, nprime)
	Hprime := make([]ECPoint, nprime)

	xinv := new(big.Int).ModInverse(x, EC.N)

	// Gprime = xinv * G[:nprime] + x*G[nprime:]
	// Hprime = x * H[:nprime] + xinv*H[nprime:]

	for i := range Gprime {
		//fmt.Printf("i: %d && i+nprime: %d\n", i, i+nprime)
		Gprime[i] = G[i].Mult(xinv).Add(G[i+nprime].Mult(x))
		Hprime[i] = H[i].Mult(x).Add(H[i+nprime].Mult(xinv))
	}

	x2 := new(big.Int).Mod(new(big.Int).Mul(x, x), EC.N)
	xinv2 := new(big.Int).ModInverse(x2, EC.N)

	Pprime := L.Mult(x2).Add(P).Add(R.Mult(xinv2)) // x^2 * L + P + xinv^2 * R

	return Gprime, Hprime, Pprime
}

// InnerProduct - The length here always has to be a power of two
func InnerProduct(a []*big.Int, b []*big.Int) *big.Int {
	if len(a) != len(b) {
		fmt.Println("InnerProduct: Uh oh! Arrays not of the same length")
		fmt.Printf("len(a): %d\n", len(a))
		fmt.Printf("len(b): %d\n", len(b))
	}

	c := big.NewInt(0)

	for i := range a {
		tmp1 := new(big.Int).Mul(a[i], b[i])
		c = new(big.Int).Add(c, new(big.Int).Mod(tmp1, EC.N))
	}

	return new(big.Int).Mod(c, EC.N)
}

//VectorAdd - adds the vector arrays
func VectorAdd(v []*big.Int, w []*big.Int) []*big.Int {
	if len(v) != len(w) {
		fmt.Println("VectorAdd: Uh oh! Arrays not of the same length")
		fmt.Printf("len(v): %d\n", len(v))
		fmt.Printf("len(w): %d\n", len(w))
	}
	result := make([]*big.Int, len(v))

	for i := range v {
		result[i] = new(big.Int).Mod(new(big.Int).Add(v[i], w[i]), EC.N)
	}

	return result
}

// VectorHadamard - add more details later
func VectorHadamard(v, w []*big.Int) []*big.Int {
	if len(v) != len(w) {
		fmt.Println("VectorHadamard: Uh oh! Arrays not of the same length")
		fmt.Printf("len(v): %d\n", len(w))
		fmt.Printf("len(w): %d\n", len(v))
	}

	result := make([]*big.Int, len(v))

	for i := range v {
		result[i] = new(big.Int).Mod(new(big.Int).Mul(v[i], w[i]), EC.N)
	}

	return result
}

// VectorAddScalar - adds scalar vectors together
func VectorAddScalar(v []*big.Int, s *big.Int) []*big.Int {
	result := make([]*big.Int, len(v))

	for i := range v {
		result[i] = new(big.Int).Mod(new(big.Int).Add(v[i], s), EC.N)
	}

	return result
}

// ScalarVectorMul - multiplies two scalar vectors together
func ScalarVectorMul(v []*big.Int, s *big.Int) []*big.Int {
	result := make([]*big.Int, len(v))

	for i := range v {
		result[i] = new(big.Int).Mod(new(big.Int).Mul(v[i], s), EC.N)
	}

	return result
}

/*
InnerProductProveSub - Inner Product Argument
Proves that <a,b>=c
This is a building block for BulletProofs
*/
func InnerProductProveSub(proof InnerProdArg, G, H []ECPoint, a []*big.Int, b []*big.Int, u ECPoint, P ECPoint) InnerProdArg {
	//fmt.Printf("Proof so far: %s\n", proof)
	if len(a) == 1 {
		// Prover sends a & b
		//fmt.Printf("a: %d && b: %d\n", a[0], b[0])
		proof.A = a[0]
		proof.B = b[0]
		return proof
	}

	curIt := int(math.Log2(float64(len(a)))) - 1

	nprime := len(a) / 2
	cl := InnerProduct(a[:nprime], b[nprime:]) // either this line
	cr := InnerProduct(a[nprime:], b[:nprime]) // or this line
	L := TwoVectorPCommitWithGens(G[nprime:], H[:nprime], a[:nprime], b[nprime:]).Add(u.Mult(cl))
	R := TwoVectorPCommitWithGens(G[:nprime], H[nprime:], a[nprime:], b[:nprime]).Add(u.Mult(cr))

	proof.L[curIt] = L
	proof.R[curIt] = R

	// prover sends L & R and gets a challenge
	s256 := sha256.Sum256([]byte(
		L.X.String() + L.Y.String() +
			R.X.String() + R.Y.String()))

	x := new(big.Int).SetBytes(s256[:])

	proof.Challenges[curIt] = x

	Gprime, Hprime, Pprime := GenerateNewParams(G, H, x, L, R, P)
	xinv := new(big.Int).ModInverse(x, EC.N)

	// or these two lines
	aprime := VectorAdd(
		ScalarVectorMul(a[:nprime], x),
		ScalarVectorMul(a[nprime:], xinv))
	bprime := VectorAdd(
		ScalarVectorMul(b[:nprime], xinv),
		ScalarVectorMul(b[nprime:], x))

	return InnerProductProveSub(proof, Gprime, Hprime, aprime, bprime, u, Pprime)
}

// InnerProductProve - validate the inner product
func InnerProductProve(a []*big.Int, b []*big.Int, c *big.Int, P, U ECPoint, G, H []ECPoint) InnerProdArg {
	loglen := int(math.Log2(float64(len(a))))

	challenges := make([]*big.Int, loglen+1)
	Lvals := make([]ECPoint, loglen)
	Rvals := make([]ECPoint, loglen)

	runningProof := InnerProdArg{
		Lvals,
		Rvals,
		big.NewInt(0),
		big.NewInt(0),
		challenges}

	// randomly generate an x value from public data
	x := sha256.Sum256([]byte(P.X.String() + P.Y.String()))

	runningProof.Challenges[loglen] = new(big.Int).SetBytes(x[:])

	Pprime := P.Add(U.Mult(new(big.Int).Mul(new(big.Int).SetBytes(x[:]), c)))
	ux := U.Mult(new(big.Int).SetBytes(x[:]))
	//fmt.Printf("Prover Pprime value to run sub off of: %s\n", Pprime)
	return InnerProductProveSub(runningProof, G, H, a, b, ux, Pprime)
}

/*
InnerProductVerify
Given a inner product proof, verifies the correctness of the proof

Since we're using the Fiat-Shamir transform, we need to verify all x hash computations,
all g' and h' computations

P : the Pedersen commitment we are verifying is a commitment to the innner product
ipp : the proof
*/
func InnerProductVerify(c *big.Int, P, U ECPoint, G, H []ECPoint, ipp InnerProdArg) bool {
	fmt.Println("Verifying Inner Product Argument")
	fmt.Printf("Commitment Value: %s \n", P)
	s1 := sha256.Sum256([]byte(P.X.String() + P.Y.String()))
	chal1 := new(big.Int).SetBytes(s1[:])
	ux := U.Mult(chal1)
	curIt := len(ipp.Challenges) - 1

	if ipp.Challenges[curIt].Cmp(chal1) != 0 {
		fmt.Println("IPVerify - Initial Challenge Failed")
		return false
	}

	curIt--

	Gprime := G
	Hprime := H
	Pprime := P.Add(ux.Mult(c)) // line 6 from protocol 1
	//fmt.Printf("New Commitment value with u^cx: %s \n", Pprime)

	for curIt >= 0 {
		Lval := ipp.L[curIt]
		Rval := ipp.R[curIt]

		// prover sends L & R and gets a challenge
		s256 := sha256.Sum256([]byte(
			Lval.X.String() + Lval.Y.String() +
				Rval.X.String() + Rval.Y.String()))

		chal2 := new(big.Int).SetBytes(s256[:])

		if ipp.Challenges[curIt].Cmp(chal2) != 0 {
			fmt.Println("IPVerify - Challenge verification failed at index " + strconv.Itoa(curIt))
			return false
		}

		Gprime, Hprime, Pprime = GenerateNewParams(Gprime, Hprime, chal2, Lval, Rval, Pprime)
		curIt--
	}
	ccalc := new(big.Int).Mod(new(big.Int).Mul(ipp.A, ipp.B), EC.N)

	Pcalc1 := Gprime[0].Mult(ipp.A)
	Pcalc2 := Hprime[0].Mult(ipp.B)
	Pcalc3 := ux.Mult(ccalc)
	Pcalc := Pcalc1.Add(Pcalc2).Add(Pcalc3)

	if !Pprime.Equal(Pcalc) {
		fmt.Println("IPVerify - Final Commitment checking failed")
		fmt.Printf("Final Pprime value: %s \n", Pprime)
		fmt.Printf("Calculated Pprime value to check against: %s \n", Pcalc)
		return false
	}

	return true
}

/*
InnerProductVerifyFast
Given a inner product proof, verifies the correctness of the proof. Does the same as above except
we replace n separate exponentiations with a single multi-exponentiation.
*/
func InnerProductVerifyFast(c *big.Int, P, U ECPoint, G, H []ECPoint, ipp InnerProdArg) bool {
	fmt.Println("Verifying Inner Product Argument")
	fmt.Printf("Commitment Value: %s \n", P)
	s1 := sha256.Sum256([]byte(P.X.String() + P.Y.String()))
	chal1 := new(big.Int).SetBytes(s1[:])
	ux := U.Mult(chal1)
	curIt := len(ipp.Challenges) - 1

	// check all challenges
	if ipp.Challenges[curIt].Cmp(chal1) != 0 {
		fmt.Println("IPVerify - Initial Challenge Failed")
		return false
	}

	for j := curIt - 1; j >= 0; j-- {
		Lval := ipp.L[j]
		Rval := ipp.R[j]

		// prover sends L & R and gets a challenge
		s256 := sha256.Sum256([]byte(
			Lval.X.String() + Lval.Y.String() +
				Rval.X.String() + Rval.Y.String()))

		chal2 := new(big.Int).SetBytes(s256[:])

		if ipp.Challenges[j].Cmp(chal2) != 0 {
			fmt.Println("IPVerify - Challenge verification failed at index " + strconv.Itoa(j))
			return false
		}
	}
	// begin computing

	curIt--
	Pprime := P.Add(ux.Mult(c)) // line 6 from protocol 1

	tmp1 := EC.Zero()
	for j := curIt; j >= 0; j-- {
		x2 := new(big.Int).Exp(ipp.Challenges[j], big.NewInt(2), EC.N)
		x2i := new(big.Int).ModInverse(x2, EC.N)
		//fmt.Println(tmp1)
		tmp1 = ipp.L[j].Mult(x2).Add(ipp.R[j].Mult(x2i)).Add(tmp1)
		//fmt.Println(tmp1)
	}
	rhs := Pprime.Add(tmp1)

	sScalars := make([]*big.Int, EC.V)
	invsScalars := make([]*big.Int, EC.V)

	for i := 0; i < EC.V; i++ {
		si := big.NewInt(1)
		for j := curIt; j >= 0; j-- {
			// original challenge if the jth bit of i is 1, inverse challenge otherwise
			chal := ipp.Challenges[j]
			if big.NewInt(int64(i)).Bit(j) == 0 {
				chal = new(big.Int).ModInverse(chal, EC.N)
			}
			// fmt.Printf("Challenge raised to value: %d\n", chal)
			si = new(big.Int).Mod(new(big.Int).Mul(si, chal), EC.N)
		}
		//fmt.Printf("Si value: %d\n", si)
		sScalars[i] = si
		invsScalars[i] = new(big.Int).ModInverse(si, EC.N)
	}

	ccalc := new(big.Int).Mod(new(big.Int).Mul(ipp.A, ipp.B), EC.N)
	lhs := TwoVectorPCommitWithGens(G, H, ScalarVectorMul(sScalars, ipp.A), ScalarVectorMul(invsScalars, ipp.B)).Add(ux.Mult(ccalc))

	if !rhs.Equal(lhs) {
		fmt.Println("IPVerify - Final Commitment checking failed")
		fmt.Printf("Final rhs value: %s \n", rhs)
		fmt.Printf("Final lhs value: %s \n", lhs)
		return false
	}

	return true
}

// PadLeft - from here: https://play.golang.org/p/zciRZvD0Gr with a fix
func PadLeft(str, pad string, l int) string {
	strCopy := str
	for len(strCopy) < l {
		strCopy = pad + strCopy
	}

	return strCopy
}

// STRNot
func STRNot(str string) string {
	result := ""

	for _, i := range str {
		if i == '0' {
			result += "1"
		} else {
			result += "0"
		}
	}
	return result
}

func StrToBigIntArray(str string) []*big.Int {
	result := make([]*big.Int, len(str))

	for i := range str {
		t, success := new(big.Int).SetString(string(str[i]), 10)
		if success {
			result[i] = t
		}
	}

	return result
}

func reverse(l []*big.Int) []*big.Int {
	result := make([]*big.Int, len(l))

	for i := range l {
		result[i] = l[len(l)-i-1]
	}

	return result
}

func PowerVector(l int, base *big.Int) []*big.Int {
	result := make([]*big.Int, l)

	for i := 0; i < l; i++ {
		result[i] = new(big.Int).Exp(base, big.NewInt(int64(i)), EC.N)
	}

	return result
}

func RandVector(l int) []*big.Int {
	result := make([]*big.Int, l)

	for i := 0; i < l; i++ {
		x, err := rand.Int(rand.Reader, EC.N)
		check(err)
		result[i] = x
	}

	return result
}

func VectorSum(y []*big.Int) *big.Int {
	result := big.NewInt(0)

	for _, j := range y {
		result = new(big.Int).Mod(new(big.Int).Add(result, j), EC.N)
	}

	return result
}

type RangeProof struct {
	Comm Commitment
	A    ECPoint
	S    ECPoint
	T1   ECPoint
	T2   ECPoint
	Tau  *big.Int
	Th   *big.Int
	Mu   *big.Int
	IPP  InnerProdArg

	// challenges
	Cy *big.Int
	Cz *big.Int
	Cx *big.Int
}

/*
Delta is a helper function that is used in the range proof

\delta(y, z) = (z-z^2)<1^n, y^n> - z^3<1^n, 2^n>
*/

func Delta(y []*big.Int, z *big.Int) *big.Int {
	result := big.NewInt(0)

	// (z-z^2)<1^n, y^n>
	z2 := new(big.Int).Mod(new(big.Int).Mul(z, z), EC.N)
	t1 := new(big.Int).Mod(new(big.Int).Sub(z, z2), EC.N)
	t2 := new(big.Int).Mod(new(big.Int).Mul(t1, VectorSum(y)), EC.N)

	// z^3<1^n, 2^n>
	z3 := new(big.Int).Mod(new(big.Int).Mul(z2, z), EC.N)
	po2sum := new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(EC.V)), EC.N), big.NewInt(1))
	t3 := new(big.Int).Mod(new(big.Int).Mul(z3, po2sum), EC.N)

	result = new(big.Int).Mod(new(big.Int).Sub(t2, t3), EC.N)

	return result
}

// Calculates (aL - z*1^n) + sL*x
func CalculateL(aL, sL []*big.Int, z, x *big.Int) []*big.Int {
	result := make([]*big.Int, len(aL))

	tmp1 := VectorAddScalar(aL, new(big.Int).Neg(z))
	tmp2 := ScalarVectorMul(sL, x)

	result = VectorAdd(tmp1, tmp2)

	return result
}

func CalculateR(aR, sR, y, po2 []*big.Int, z, x *big.Int) []*big.Int {
	if len(aR) != len(sR) || len(aR) != len(y) || len(y) != len(po2) {
		fmt.Println("CalculateR: Uh oh! Arrays not of the same length")
		fmt.Printf("len(aR): %d\n", len(aR))
		fmt.Printf("len(sR): %d\n", len(sR))
		fmt.Printf("len(y): %d\n", len(y))
		fmt.Printf("len(po2): %d\n", len(po2))
	}

	result := make([]*big.Int, len(aR))

	z2 := new(big.Int).Exp(z, big.NewInt(2), EC.N)
	tmp11 := VectorAddScalar(aR, z)
	tmp12 := ScalarVectorMul(sR, x)
	tmp1 := VectorHadamard(y, VectorAdd(tmp11, tmp12))
	tmp2 := ScalarVectorMul(po2, z2)

	result = VectorAdd(tmp1, tmp2)

	return result
}

/*
RPProver : Range Proof Prove

Given a value v, provides a range proof that v is inside 0 to 2^64-1
*/
func RPProve(v *big.Int) RangeProof {

	rpresult := RangeProof{}

	PowerOfTwos := PowerVector(EC.V, big.NewInt(2))

	if v.Cmp(big.NewInt(0)) == -1 {
		panic("Value is below range! Not proving")
	}

	if v.Cmp(new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(EC.V)), EC.N)) == 1 {
		panic("Value is above range! Not proving.")
	}

	gamma, err := rand.Int(rand.Reader, EC.N)
	check(err)
	comm := EC.G.Mult(v).Add(EC.H.Mult(gamma))
	rpresult.Comm.Comm = comm

	// break up v into its bitwise representation
	//aL := 0
	aL := reverse(StrToBigIntArray(PadLeft(fmt.Sprintf("%b", v), "0", EC.V)))
	aR := VectorAddScalar(aL, big.NewInt(-1))

	alpha, err := rand.Int(rand.Reader, EC.N)
	check(err)

	A := TwoVectorPCommitWithGens(EC.BPG, EC.BPH, aL, aR).Add(EC.H.Mult(alpha))
	rpresult.A = A

	sL := RandVector(EC.V)
	sR := RandVector(EC.V)

	rho, err := rand.Int(rand.Reader, EC.N)
	check(err)

	S := TwoVectorPCommitWithGens(EC.BPG, EC.BPH, sL, sR).Add(EC.H.Mult(rho))
	rpresult.S = S

	chal1s256 := sha256.Sum256([]byte(A.X.String() + A.Y.String()))
	cy := new(big.Int).SetBytes(chal1s256[:])

	chal2s256 := sha256.Sum256([]byte(S.X.String() + S.Y.String()))
	cz := new(big.Int).SetBytes(chal2s256[:])

	z2 := new(big.Int).Exp(cz, big.NewInt(2), EC.N)
	// need to generate l(X), r(X), and t(X)=<l(X),r(X)>

	/*
			Java code on how to calculate t1 and t2

				FieldVector ys = FieldVector.from(VectorX.iterate(n, BigInteger.ONE, y::multiply),q); //powers of y
			    FieldVector l0 = aL.add(z.negate());
		        FieldVector l1 = sL;
		        FieldVector twoTimesZSquared = twos.times(zSquared);
		        FieldVector r0 = ys.hadamard(aR.add(z)).add(twoTimesZSquared);
		        FieldVector r1 = sR.hadamard(ys);
		        BigInteger k = ys.sum().multiply(z.subtract(zSquared)).subtract(zCubed.shiftLeft(n).subtract(zCubed));
		        BigInteger t0 = k.add(zSquared.multiply(number));
		        BigInteger t1 = l1.innerPoduct(r0).add(l0.innerPoduct(r1));
		        BigInteger t2 = l1.innerPoduct(r1);
		   		PolyCommitment<T> polyCommitment = PolyCommitment.from(base, t0, VectorX.of(t1, t2));


	*/
	PowerOfCY := PowerVector(EC.V, cy)
	// fmt.Println(PowerOfCY)
	l0 := VectorAddScalar(aL, new(big.Int).Neg(cz))
	// l1 := sL
	r0 := VectorAdd(
		VectorHadamard(
			PowerOfCY,
			VectorAddScalar(aR, cz)),
		ScalarVectorMul(
			PowerOfTwos,
			z2))
	r1 := VectorHadamard(sR, PowerOfCY)

	//calculate t0
	t0 := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(v, z2), Delta(PowerOfCY, cz)), EC.N)

	t1 := new(big.Int).Mod(new(big.Int).Add(InnerProduct(sL, r0), InnerProduct(l0, r1)), EC.N)
	t2 := InnerProduct(sL, r1)

	// given the t_i values, we can generate commitments to them
	tau1, err := rand.Int(rand.Reader, EC.N)
	check(err)
	tau2, err := rand.Int(rand.Reader, EC.N)
	check(err)

	T1 := EC.G.Mult(t1).Add(EC.H.Mult(tau1)) //commitment to t1
	T2 := EC.G.Mult(t2).Add(EC.H.Mult(tau2)) //commitment to t2

	rpresult.T1 = T1
	rpresult.T2 = T2

	chal3s256 := sha256.Sum256([]byte(T1.X.String() + T1.Y.String() + T2.X.String() + T2.Y.String()))
	cx := new(big.Int).SetBytes(chal3s256[:])

	left := CalculateL(aL, sL, cz, cx)
	right := CalculateR(aR, sR, PowerOfCY, PowerOfTwos, cz, cx)

	thatPrime := new(big.Int).Mod( // t0 + t1*x + t2*x^2
		new(big.Int).Add(
			t0,
			new(big.Int).Add(
				new(big.Int).Mul(
					t1, cx),
				new(big.Int).Mul(
					new(big.Int).Mul(cx, cx),
					t2))), EC.N)

	that := InnerProduct(left, right) // NOTE: BP Java implementation calculates this from the t_i

	// thatPrime and that should be equal
	if thatPrime.Cmp(that) != 0 {
		fmt.Println("Proving -- Uh oh! Two diff ways to compute same value not working")
		fmt.Printf("\tthatPrime = %s\n", thatPrime.String())
		fmt.Printf("\tthat = %s \n", that.String())
	}

	rpresult.Th = thatPrime

	taux1 := new(big.Int).Mod(new(big.Int).Mul(tau2, new(big.Int).Mul(cx, cx)), EC.N)
	taux2 := new(big.Int).Mod(new(big.Int).Mul(tau1, cx), EC.N)
	taux3 := new(big.Int).Mod(new(big.Int).Mul(z2, gamma), EC.N)
	taux := new(big.Int).Mod(new(big.Int).Add(taux1, new(big.Int).Add(taux2, taux3)), EC.N)

	rpresult.Tau = taux

	mu := new(big.Int).Mod(new(big.Int).Add(alpha, new(big.Int).Mul(rho, cx)), EC.N)
	rpresult.Mu = mu

	HPrime := make([]ECPoint, len(EC.BPH))

	for i := range HPrime {
		HPrime[i] = EC.BPH[i].Mult(new(big.Int).ModInverse(PowerOfCY[i], EC.N))
	}

	// for testing
	tmp1 := EC.Zero()
	zneg := new(big.Int).Mod(new(big.Int).Neg(cz), EC.N)
	for i := range EC.BPG {
		tmp1 = tmp1.Add(EC.BPG[i].Mult(zneg))
	}

	tmp2 := EC.Zero()
	for i := range HPrime {
		val1 := new(big.Int).Mul(cz, PowerOfCY[i])
		val2 := new(big.Int).Mul(new(big.Int).Mul(cz, cz), PowerOfTwos[i])
		tmp2 = tmp2.Add(HPrime[i].Mult(new(big.Int).Add(val1, val2)))
	}

	P1 := A.Add(S.Mult(cx)).Add(tmp1).Add(tmp2).Add(EC.U.Mult(that)).Add(EC.H.Mult(mu).Neg())

	P2 := TwoVectorPCommitWithGens(EC.BPG, HPrime, left, right)
	fmt.Println(P1)
	fmt.Println(P2)

	rpresult.IPP = InnerProductProve(left, right, that, P2, EC.U, EC.BPG, HPrime)

	return rpresult
}

/*
RPProveTrans : Range Proof Prover customised for transactions

Given a value v, provides a range proof that v is inside 0 to 2^64-1
*/
func RPProveTrans(gamma *big.Int, v *big.Int) RangeProof {

	rpresult := RangeProof{}

	PowerOfTwos := PowerVector(EC.V, big.NewInt(2))

	if v.Cmp(big.NewInt(0)) == -1 {
		panic("Value is below range! Not proving")
	}

	if v.Cmp(new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(EC.V)), EC.N)) == 1 {
		panic("Value is above range! Not proving.")
	}

	comm := EC.G.Mult(v).Add(EC.H.Mult(gamma))
	rpresult.Comm.Comm = comm

	// break up v into its bitwise representation
	//aL := 0
	aL := reverse(StrToBigIntArray(PadLeft(fmt.Sprintf("%b", v), "0", EC.V)))
	aR := VectorAddScalar(aL, big.NewInt(-1))

	alpha, err := rand.Int(rand.Reader, EC.N)
	check(err)

	A := TwoVectorPCommitWithGens(EC.BPG, EC.BPH, aL, aR).Add(EC.H.Mult(alpha))
	rpresult.A = A

	sL := RandVector(EC.V)
	sR := RandVector(EC.V)

	rho, err := rand.Int(rand.Reader, EC.N)
	check(err)

	S := TwoVectorPCommitWithGens(EC.BPG, EC.BPH, sL, sR).Add(EC.H.Mult(rho))
	rpresult.S = S

	chal1s256 := sha256.Sum256([]byte(A.X.String() + A.Y.String()))
	cy := new(big.Int).SetBytes(chal1s256[:])

	chal2s256 := sha256.Sum256([]byte(S.X.String() + S.Y.String()))
	cz := new(big.Int).SetBytes(chal2s256[:])

	z2 := new(big.Int).Exp(cz, big.NewInt(2), EC.N)
	// need to generate l(X), r(X), and t(X)=<l(X),r(X)>

	/*
			Java code on how to calculate t1 and t2

				FieldVector ys = FieldVector.from(VectorX.iterate(n, BigInteger.ONE, y::multiply),q); //powers of y
			    FieldVector l0 = aL.add(z.negate());
		        FieldVector l1 = sL;
		        FieldVector twoTimesZSquared = twos.times(zSquared);
		        FieldVector r0 = ys.hadamard(aR.add(z)).add(twoTimesZSquared);
		        FieldVector r1 = sR.hadamard(ys);
		        BigInteger k = ys.sum().multiply(z.subtract(zSquared)).subtract(zCubed.shiftLeft(n).subtract(zCubed));
		        BigInteger t0 = k.add(zSquared.multiply(number));
		        BigInteger t1 = l1.innerPoduct(r0).add(l0.innerPoduct(r1));
		        BigInteger t2 = l1.innerPoduct(r1);
		   		PolyCommitment<T> polyCommitment = PolyCommitment.from(base, t0, VectorX.of(t1, t2));


	*/
	PowerOfCY := PowerVector(EC.V, cy)
	// fmt.Println(PowerOfCY)
	l0 := VectorAddScalar(aL, new(big.Int).Neg(cz))
	// l1 := sL
	r0 := VectorAdd(
		VectorHadamard(
			PowerOfCY,
			VectorAddScalar(aR, cz)),
		ScalarVectorMul(
			PowerOfTwos,
			z2))
	r1 := VectorHadamard(sR, PowerOfCY)

	//calculate t0
	t0 := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(v, z2), Delta(PowerOfCY, cz)), EC.N)

	t1 := new(big.Int).Mod(new(big.Int).Add(InnerProduct(sL, r0), InnerProduct(l0, r1)), EC.N)
	t2 := InnerProduct(sL, r1)

	// given the t_i values, we can generate commitments to them
	tau1, err := rand.Int(rand.Reader, EC.N)
	check(err)
	tau2, err := rand.Int(rand.Reader, EC.N)
	check(err)

	T1 := EC.G.Mult(t1).Add(EC.H.Mult(tau1)) //commitment to t1
	T2 := EC.G.Mult(t2).Add(EC.H.Mult(tau2)) //commitment to t2

	rpresult.T1 = T1
	rpresult.T2 = T2

	chal3s256 := sha256.Sum256([]byte(T1.X.String() + T1.Y.String() + T2.X.String() + T2.Y.String()))
	cx := new(big.Int).SetBytes(chal3s256[:])

	left := CalculateL(aL, sL, cz, cx)
	right := CalculateR(aR, sR, PowerOfCY, PowerOfTwos, cz, cx)

	thatPrime := new(big.Int).Mod( // t0 + t1*x + t2*x^2
		new(big.Int).Add(
			t0,
			new(big.Int).Add(
				new(big.Int).Mul(
					t1, cx),
				new(big.Int).Mul(
					new(big.Int).Mul(cx, cx),
					t2))), EC.N)

	that := InnerProduct(left, right) // NOTE: BP Java implementation calculates this from the t_i

	// thatPrime and that should be equal
	if thatPrime.Cmp(that) != 0 {
		fmt.Println("Proving -- Uh oh! Two diff ways to compute same value not working")
		fmt.Printf("\tthatPrime = %s\n", thatPrime.String())
		fmt.Printf("\tthat = %s \n", that.String())
	}

	rpresult.Th = thatPrime

	taux1 := new(big.Int).Mod(new(big.Int).Mul(tau2, new(big.Int).Mul(cx, cx)), EC.N)
	taux2 := new(big.Int).Mod(new(big.Int).Mul(tau1, cx), EC.N)
	taux3 := new(big.Int).Mod(new(big.Int).Mul(z2, gamma), EC.N)
	taux := new(big.Int).Mod(new(big.Int).Add(taux1, new(big.Int).Add(taux2, taux3)), EC.N)

	rpresult.Tau = taux

	mu := new(big.Int).Mod(new(big.Int).Add(alpha, new(big.Int).Mul(rho, cx)), EC.N)
	rpresult.Mu = mu

	HPrime := make([]ECPoint, len(EC.BPH))

	for i := range HPrime {
		HPrime[i] = EC.BPH[i].Mult(new(big.Int).ModInverse(PowerOfCY[i], EC.N))
	}


	P := TwoVectorPCommitWithGens(EC.BPG, HPrime, left, right)

	rpresult.IPP = InnerProductProve(left, right, that, P, EC.U, EC.BPG, HPrime)

	return rpresult
}

func RPVerify(rp RangeProof) bool {
	// create the challenge variables
	chal1s256 := sha256.Sum256([]byte(rp.A.X.String() + rp.A.Y.String()))
	cy := new(big.Int).SetBytes(chal1s256[:])

	chal2s256 := sha256.Sum256([]byte(rp.S.X.String() + rp.S.Y.String()))
	cz := new(big.Int).SetBytes(chal2s256[:])

	chal3s256 := sha256.Sum256([]byte(rp.T1.X.String() + rp.T1.Y.String() + rp.T2.X.String() + rp.T2.Y.String()))
	cx := new(big.Int).SetBytes(chal3s256[:])

	// given challenges are correct, very range proof
	PowersOfY := PowerVector(EC.V, cy)

	// t_hat * G + tau * H
	lhs := EC.G.Mult(rp.Th).Add(EC.H.Mult(rp.Tau))

	// z^2 * V + delta(y,z) * G + x * T1 + x^2 * T2
	rhs := rp.Comm.Comm.Mult(new(big.Int).Mul(cz, cz)).Add(
		EC.G.Mult(Delta(PowersOfY, cz))).Add(
		rp.T1.Mult(cx)).Add(
		rp.T2.Mult(new(big.Int).Mul(cx, cx)))

	if !lhs.Equal(rhs) {
		fmt.Println("RPVerify - Uh oh! Check line (63) of verification")
		fmt.Println(rhs)
		fmt.Println(lhs)
		return false
	}

	tmp1 := EC.Zero()
	zneg := new(big.Int).Mod(new(big.Int).Neg(cz), EC.N)
	for i := range EC.BPG {
		tmp1 = tmp1.Add(EC.BPG[i].Mult(zneg))
	}

	PowerOfTwos := PowerVector(EC.V, big.NewInt(2))
	tmp2 := EC.Zero()
	// generate h'
	HPrime := make([]ECPoint, len(EC.BPH))

	for i := range HPrime {
		mi := new(big.Int).ModInverse(PowersOfY[i], EC.N)
		HPrime[i] = EC.BPH[i].Mult(mi)
	}

	for i := range HPrime {
		val1 := new(big.Int).Mul(cz, PowersOfY[i])
		val2 := new(big.Int).Mul(new(big.Int).Mul(cz, cz), PowerOfTwos[i])
		tmp2 = tmp2.Add(HPrime[i].Mult(new(big.Int).Add(val1, val2)))
	}

	// without subtracting this value should equal muCH + l[i]G[i] + r[i]H'[i]
	// we want to make sure that the innerproduct checks out, so we subtract it
	P := rp.A.Add(rp.S.Mult(cx)).Add(tmp1).Add(tmp2).Add(EC.H.Mult(rp.Mu).Neg())
	//fmt.Println(P)

	if !InnerProductVerifyFast(rp.Th, P, EC.U, EC.BPG, HPrime, rp.IPP) {
		fmt.Println("RPVerify - Uh oh! Check line (65) of verification!")
		return false
	}

	return true
}

func RPVerifyTrans(comm *ECPoint, rp *RangeProof) bool {
	// Create the challenges
	chal1s256 := sha256.Sum256([]byte(rp.A.X.String() + rp.A.Y.String()))
	cy := new(big.Int).SetBytes(chal1s256[:])

	chal2s256 := sha256.Sum256([]byte(rp.S.X.String() + rp.S.Y.String()))
	cz := new(big.Int).SetBytes(chal2s256[:])

	chal3s256 := sha256.Sum256([]byte(rp.T1.X.String() + rp.T1.Y.String() + rp.T2.X.String() + rp.T2.Y.String()))
	cx := new(big.Int).SetBytes(chal3s256[:])

	// given challenges are correct, very range proof
	PowersOfY := PowerVector(EC.V, cy)

	// t_hat * G + tau * H
	lhs := EC.G.Mult(rp.Th).Add(EC.H.Mult(rp.Tau))

	// z^2 * V + delta(y,z) * G + x * T1 + x^2 * T2
	rhs := comm.Mult(new(big.Int).Mul(cz, cz)).Add(
		EC.G.Mult(Delta(PowersOfY, cz))).Add(
		rp.T1.Mult(cx)).Add(
		rp.T2.Mult(new(big.Int).Mul(cx, cx)))

	if !lhs.Equal(rhs) {
		fmt.Println("RPVerify - Uh oh! Check line (63) of verification")
		fmt.Println(rhs)
		fmt.Println(lhs)
		return false
	}

	tmp1 := EC.Zero()
	zneg := new(big.Int).Mod(new(big.Int).Neg(cz), EC.N)
	for i := range EC.BPG {
		tmp1 = tmp1.Add(EC.BPG[i].Mult(zneg))
	}

	PowerOfTwos := PowerVector(EC.V, big.NewInt(2))
	tmp2 := EC.Zero()
	// generate h'
	HPrime := make([]ECPoint, len(EC.BPH))

	for i := range HPrime {
		mi := new(big.Int).ModInverse(PowersOfY[i], EC.N)
		HPrime[i] = EC.BPH[i].Mult(mi)
	}

	for i := range HPrime {
		val1 := new(big.Int).Mul(cz, PowersOfY[i])
		val2 := new(big.Int).Mul(new(big.Int).Mul(cz, cz), PowerOfTwos[i])
		tmp2 = tmp2.Add(HPrime[i].Mult(new(big.Int).Add(val1, val2)))
	}

	// without subtracting this value should equal muCH + l[i]G[i] + r[i]H'[i]
	// we want to make sure that the innerproduct checks out, so we subtract it
	P := rp.A.Add(rp.S.Mult(cx)).Add(tmp1).Add(tmp2).Add(EC.H.Mult(rp.Mu).Neg())
	//fmt.Println(P)

	if !InnerProductVerifyFast(rp.Th, P, EC.U, EC.BPG, HPrime, rp.IPP) {
		fmt.Println("RPVerify - Uh oh! Check line (65) of verification!")
		return false
	}

	return true
}

// Calculates (aL - z*1^n) + sL*x
func CalculateLMRP(aL, sL []*big.Int, z, x *big.Int) []*big.Int {
	result := make([]*big.Int, len(aL))

	tmp1 := VectorAddScalar(aL, new(big.Int).Neg(z))
	tmp2 := ScalarVectorMul(sL, x)

	result = VectorAdd(tmp1, tmp2)

	return result
}

func CalculateRMRP(aR, sR, y, zTimesTwo []*big.Int, z, x *big.Int) []*big.Int {
	if len(aR) != len(sR) || len(aR) != len(y) || len(y) != len(zTimesTwo) {
		fmt.Println("CalculateR: Uh oh! Arrays not of the same length")
		fmt.Printf("len(aR): %d\n", len(aR))
		fmt.Printf("len(sR): %d\n", len(sR))
		fmt.Printf("len(y): %d\n", len(y))
		fmt.Printf("len(po2): %d\n", len(zTimesTwo))
	}

	result := make([]*big.Int, len(aR))

	tmp11 := VectorAddScalar(aR, z)
	tmp12 := ScalarVectorMul(sR, x)
	tmp1 := VectorHadamard(y, VectorAdd(tmp11, tmp12))

	result = VectorAdd(tmp1, zTimesTwo)

	return result
}

/*
DeltaMRP is a helper function that is used in the multi range proof

\delta(y, z) = (z-z^2)<1^n, y^n> - \sum_j z^3+j<1^n, 2^n>
*/

func DeltaMRP(y []*big.Int, z *big.Int, m int) *big.Int {
	result := big.NewInt(0)

	// (z-z^2)<1^n, y^n>
	z2 := new(big.Int).Mod(new(big.Int).Mul(z, z), EC.N)
	t1 := new(big.Int).Mod(new(big.Int).Sub(z, z2), EC.N)
	t2 := new(big.Int).Mod(new(big.Int).Mul(t1, VectorSum(y)), EC.N)

	// \sum_j z^3+j<1^n, 2^n>
	// <1^n, 2^n> = 2^n - 1
	po2sum := new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(EC.V/m)), EC.N), big.NewInt(1))
	t3 := big.NewInt(0)

	for j := 0; j < m; j++ {
		zp := new(big.Int).Exp(z, big.NewInt(3+int64(j)), EC.N)
		tmp1 := new(big.Int).Mod(new(big.Int).Mul(zp, po2sum), EC.N)
		t3 = new(big.Int).Mod(new(big.Int).Add(t3, tmp1), EC.N)
	}

	result = new(big.Int).Mod(new(big.Int).Sub(t2, t3), EC.N)

	return result
}

type MultiRangeProof struct {
	Comms []Commitment
	A     ECPoint
	S     ECPoint
	T1    ECPoint
	T2    ECPoint
	Tau   *big.Int
	Th    *big.Int
	Mu    *big.Int
	IPP   InnerProdArg

}


/*
MultiRangeProof Prove
Takes in a list of values and provides an aggregate
range proof for all the values.

changes:
 all values are concatenated
 r(x) is computed differently
 tau_x calculation is different
 delta calculation is different

{(g, h \in G, \textbf{V} \in G^m ; \textbf{v, \gamma} \in Z_p^m) :
	V_j = h^{\gamma_j}g^{v_j} \wedge v_j \in [0, 2^n - 1] \forall j \in [1, m]}
*/
func MRPProve(values []*big.Int) MultiRangeProof {
	// EC.V has the total number of values and bits we can support

	MRPResult := MultiRangeProof{}

	m := len(values)
	bitsPerValue := EC.V / m

	// we concatenate the binary representation of the values

	PowerOfTwos := PowerVector(bitsPerValue, big.NewInt(2))

	Comms := make([]Commitment, m)
	gammas := make([]*big.Int, m)
	aLConcat := make([]*big.Int, EC.V)
	aRConcat := make([]*big.Int, EC.V)

	for j := range values {
		v := values[j]
		if v.Cmp(big.NewInt(0)) == -1 {
			panic("Value is below range! Not proving")
		}

		if v.Cmp(new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(bitsPerValue)), EC.N)) == 1 {
			panic("Value is above range! Not proving.")
		}

		gamma, err := rand.Int(rand.Reader, EC.N)
		check(err)
		Comms[j].Comm = EC.G.Mult(v).Add(EC.H.Mult(gamma))
		gammas[j] = gamma

		// break up v into its bitwise representation
		aL := reverse(StrToBigIntArray(PadLeft(fmt.Sprintf("%b", v), "0", bitsPerValue)))
		aR := VectorAddScalar(aL, big.NewInt(-1))

		for i := range aR {
			aLConcat[bitsPerValue*j+i] = aL[i]
			aRConcat[bitsPerValue*j+i] = aR[i]
		}
	}

	MRPResult.Comms = Comms

	alpha, err := rand.Int(rand.Reader, EC.N)
	check(err)

	A := TwoVectorPCommitWithGens(EC.BPG, EC.BPH, aLConcat, aRConcat).Add(EC.H.Mult(alpha))
	MRPResult.A = A

	sL := RandVector(EC.V)
	sR := RandVector(EC.V)

	rho, err := rand.Int(rand.Reader, EC.N)
	check(err)

	S := TwoVectorPCommitWithGens(EC.BPG, EC.BPH, sL, sR).Add(EC.H.Mult(rho))
	MRPResult.S = S

	chal1s256 := sha256.Sum256([]byte(A.X.String() + A.Y.String()))
	cy := new(big.Int).SetBytes(chal1s256[:])

	chal2s256 := sha256.Sum256([]byte(S.X.String() + S.Y.String()))
	cz := new(big.Int).SetBytes(chal2s256[:])

	zPowersTimesTwoVec := make([]*big.Int, EC.V)
	for j := 0; j < m; j++ {
		zp := new(big.Int).Exp(cz, big.NewInt(2+int64(j)), EC.N)
		for i := 0; i < bitsPerValue; i++ {
			zPowersTimesTwoVec[j*bitsPerValue+i] = new(big.Int).Mod(new(big.Int).Mul(PowerOfTwos[i], zp), EC.N)
		}
	}

	PowerOfCY := PowerVector(EC.V, cy)
	// fmt.Println(PowerOfCY)
	l0 := VectorAddScalar(aLConcat, new(big.Int).Neg(cz))
	l1 := sL
	r0 := VectorAdd(
		VectorHadamard(
			PowerOfCY,
			VectorAddScalar(aRConcat, cz)),
		zPowersTimesTwoVec)
	r1 := VectorHadamard(sR, PowerOfCY)

	//calculate t0
	vz2 := big.NewInt(0)
	z2 := new(big.Int).Mod(new(big.Int).Mul(cz, cz), EC.N)
	PowerOfCZ := PowerVector(m, cz)
	for j := 0; j < m; j++ {
		vz2 = new(big.Int).Add(vz2,
			new(big.Int).Mul(
				PowerOfCZ[j],
				new(big.Int).Mul(values[j], z2)))
		vz2 = new(big.Int).Mod(vz2, EC.N)
	}

	t0 := new(big.Int).Mod(new(big.Int).Add(vz2, DeltaMRP(PowerOfCY, cz, m)), EC.N)

	t1 := new(big.Int).Mod(new(big.Int).Add(InnerProduct(l1, r0), InnerProduct(l0, r1)), EC.N)
	t2 := InnerProduct(l1, r1)

	// given the t_i values, we can generate commitments to them
	tau1, err := rand.Int(rand.Reader, EC.N)
	check(err)
	tau2, err := rand.Int(rand.Reader, EC.N)
	check(err)

	T1 := EC.G.Mult(t1).Add(EC.H.Mult(tau1)) //commitment to t1
	T2 := EC.G.Mult(t2).Add(EC.H.Mult(tau2)) //commitment to t2

	MRPResult.T1 = T1
	MRPResult.T2 = T2

	chal3s256 := sha256.Sum256([]byte(T1.X.String() + T1.Y.String() + T2.X.String() + T2.Y.String()))
	cx := new(big.Int).SetBytes(chal3s256[:])

	left := CalculateLMRP(aLConcat, sL, cz, cx)
	right := CalculateRMRP(aRConcat, sR, PowerOfCY, zPowersTimesTwoVec, cz, cx)

	thatPrime := new(big.Int).Mod( // t0 + t1*x + t2*x^2
		new(big.Int).Add(t0, new(big.Int).Add(new(big.Int).Mul(t1, cx), new(big.Int).Mul(new(big.Int).Mul(cx, cx), t2))), EC.N)

	that := InnerProduct(left, right) // NOTE: BP Java implementation calculates this from the t_i

	// thatPrime and that should be equal
	if thatPrime.Cmp(that) != 0 {
		fmt.Println("Proving -- Uh oh! Two diff ways to compute same value not working")
		fmt.Printf("\tthatPrime = %s\n", thatPrime.String())
		fmt.Printf("\tthat = %s \n", that.String())
	}

	MRPResult.Th = that

	vecRandomnessTotal := big.NewInt(0)
	for j := 0; j < m; j++ {
		zp := new(big.Int).Exp(cz, big.NewInt(2+int64(j)), EC.N)
		tmp1 := new(big.Int).Mul(gammas[j], zp)
		vecRandomnessTotal = new(big.Int).Mod(new(big.Int).Add(vecRandomnessTotal, tmp1), EC.N)
	}
	//fmt.Println(vecRandomnessTotal)
	taux1 := new(big.Int).Mod(new(big.Int).Mul(tau2, new(big.Int).Mul(cx, cx)), EC.N)
	taux2 := new(big.Int).Mod(new(big.Int).Mul(tau1, cx), EC.N)
	taux := new(big.Int).Mod(new(big.Int).Add(taux1, new(big.Int).Add(taux2, vecRandomnessTotal)), EC.N)

	MRPResult.Tau = taux

	mu := new(big.Int).Mod(new(big.Int).Add(alpha, new(big.Int).Mul(rho, cx)), EC.N)
	MRPResult.Mu = mu

	HPrime := make([]ECPoint, len(EC.BPH))

	for i := range HPrime {
		HPrime[i] = EC.BPH[i].Mult(new(big.Int).ModInverse(PowerOfCY[i], EC.N))
	}

	P := TwoVectorPCommitWithGens(EC.BPG, HPrime, left, right)
	//fmt.Println(P)

	MRPResult.IPP = InnerProductProve(left, right, that, P, EC.U, EC.BPG, HPrime)

	return MRPResult
}

/*
MultiRangeProof Prove
Takes in a list of values and provides an aggregate
range proof for all the values.

changes:
 all values are concatenated
 r(x) is computed differently
 tau_x calculation is different
 delta calculation is different

{(g, h \in G, \textbf{V} \in G^m ; \textbf{v, \gamma} \in Z_p^m) :
	V_j = h^{\gamma_j}g^{v_j} \wedge v_j \in [0, 2^n - 1] \forall j \in [1, m]}
*/
func MRPProveTrans(values []*big.Int, sSecret *big.Int) (MultiRangeProof, []ECPoint) {
	// EC.V has the total number of values and bits we can support

	MRPResult := MultiRangeProof{}

	m := len(values)
	bitsPerValue := EC.V / m

	// we concatenate the binary representation of the values

	PowerOfTwos := PowerVector(bitsPerValue, big.NewInt(2))

	Comms := make([]ECPoint, m)
	Blinds := make([]*big.Int, m)
	aLConcat := make([]*big.Int, EC.V)
	aRConcat := make([]*big.Int, EC.V)

	for j := range values {
		v := values[j]
		if v.Cmp(big.NewInt(0)) == -1 {
			panic("Value is below range! Not proving")
		}

		maxVal := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(bitsPerValue)), EC.N)

		if v.Cmp(maxVal) == 1 {
			panic("Value is above range! Not proving.")
		}

		hash := sha256.Sum256(v.Bytes())

		gamma := secp256k1.NonceRFC6979(sSecret, hash[:], nil, nil)
		Comms[j] = EC.G.Mult(v).Add(EC.H.Mult(gamma))
		Blinds[j] = gamma

		// break up v into its bitwise representation
		aL := reverse(StrToBigIntArray(PadLeft(fmt.Sprintf("%b", v), "0", bitsPerValue)))
		aR := VectorAddScalar(aL, big.NewInt(-1))

		for i := range aR {
			aLConcat[bitsPerValue*j+i] = aL[i]
			aRConcat[bitsPerValue*j+i] = aR[i]
		}
	}

	//MRPResult.Comms = Comms

	alpha, err := rand.Int(rand.Reader, EC.N)
	check(err)

	A := TwoVectorPCommitWithGens(EC.BPG, EC.BPH, aLConcat, aRConcat).Add(EC.H.Mult(alpha))
	MRPResult.A = A

	sL := RandVector(EC.V)
	sR := RandVector(EC.V)

	rho, err := rand.Int(rand.Reader, EC.N)
	check(err)

	S := TwoVectorPCommitWithGens(EC.BPG, EC.BPH, sL, sR).Add(EC.H.Mult(rho))
	MRPResult.S = S

	chal1s256 := sha256.Sum256([]byte(A.X.String() + A.Y.String()))
	cy := new(big.Int).SetBytes(chal1s256[:])

	chal2s256 := sha256.Sum256([]byte(S.X.String() + S.Y.String()))
	cz := new(big.Int).SetBytes(chal2s256[:])

	zPowersTimesTwoVec := make([]*big.Int, EC.V)
	for j := 0; j < m; j++ {
		zp := new(big.Int).Exp(cz, big.NewInt(2+int64(j)), EC.N)
		for i := 0; i < bitsPerValue; i++ {
			zPowersTimesTwoVec[j*bitsPerValue+i] = new(big.Int).Mod(new(big.Int).Mul(PowerOfTwos[i], zp), EC.N)
		}
	}


	PowerOfCY := PowerVector(EC.V, cy)
	// fmt.Println(PowerOfCY)
	l0 := VectorAddScalar(aLConcat, new(big.Int).Neg(cz))
	l1 := sL
	r0 := VectorAdd(
		VectorHadamard(
			PowerOfCY,
			VectorAddScalar(aRConcat, cz)),
		zPowersTimesTwoVec)
	r1 := VectorHadamard(sR, PowerOfCY)

	//calculate t0
	vz2 := big.NewInt(0)
	z2 := new(big.Int).Mod(new(big.Int).Mul(cz, cz), EC.N)
	PowerOfCZ := PowerVector(m, cz)
	for j := 0; j < m; j++ {
		vz2 = new(big.Int).Add(vz2,
			new(big.Int).Mul(
				PowerOfCZ[j],
				new(big.Int).Mul(values[j], z2)))
		vz2 = new(big.Int).Mod(vz2, EC.N)
	}

	t0 := new(big.Int).Mod(new(big.Int).Add(vz2, DeltaMRP(PowerOfCY, cz, m)), EC.N)

	t1 := new(big.Int).Mod(new(big.Int).Add(InnerProduct(l1, r0), InnerProduct(l0, r1)), EC.N)
	t2 := InnerProduct(l1, r1)

	// given the t_i values, we can generate commitments to them
	tau1, err := rand.Int(rand.Reader, EC.N)
	check(err)
	tau2, err := rand.Int(rand.Reader, EC.N)
	check(err)

	T1 := EC.G.Mult(t1).Add(EC.H.Mult(tau1)) //commitment to t1
	T2 := EC.G.Mult(t2).Add(EC.H.Mult(tau2)) //commitment to t2

	MRPResult.T1 = T1
	MRPResult.T2 = T2

	chal3s256 := sha256.Sum256([]byte(T1.X.String() + T1.Y.String() + T2.X.String() + T2.Y.String()))
	cx := new(big.Int).SetBytes(chal3s256[:])

	left := CalculateLMRP(aLConcat, sL, cz, cx)
	right := CalculateRMRP(aRConcat, sR, PowerOfCY, zPowersTimesTwoVec, cz, cx)

	thatPrime := new(big.Int).Mod( // t0 + t1*x + t2*x^2
		new(big.Int).Add(t0, new(big.Int).Add(new(big.Int).Mul(t1, cx), new(big.Int).Mul(new(big.Int).Mul(cx, cx), t2))), EC.N)

	that := InnerProduct(left, right) // NOTE: BP Java implementation calculates this from the t_i

	// thatPrime and that should be equal
	if thatPrime.Cmp(that) != 0 {
		fmt.Println("Proving -- Uh oh! Two diff ways to compute same value not working")
		fmt.Printf("\tthatPrime = %s\n", thatPrime.String())
		fmt.Printf("\tthat = %s \n", that.String())
	}

	MRPResult.Th = that

	vecRandomnessTotal := big.NewInt(0)
	for j := 0; j < m; j++ {
		zp := new(big.Int).Exp(cz, big.NewInt(2+int64(j)), EC.N)
		tmp1 := new(big.Int).Mul(Blinds[j], zp)
		vecRandomnessTotal = new(big.Int).Mod(new(big.Int).Add(vecRandomnessTotal, tmp1), EC.N)
	}
	//fmt.Println(vecRandomnessTotal)
	taux1 := new(big.Int).Mod(new(big.Int).Mul(tau2, new(big.Int).Mul(cx, cx)), EC.N)
	taux2 := new(big.Int).Mod(new(big.Int).Mul(tau1, cx), EC.N)
	taux := new(big.Int).Mod(new(big.Int).Add(taux1, new(big.Int).Add(taux2, vecRandomnessTotal)), EC.N)

	MRPResult.Tau = taux

	mu := new(big.Int).Mod(new(big.Int).Add(alpha, new(big.Int).Mul(rho, cx)), EC.N)
	MRPResult.Mu = mu

	HPrime := make([]ECPoint, len(EC.BPH))

	for i := range HPrime {
		HPrime[i] = EC.BPH[i].Mult(new(big.Int).ModInverse(PowerOfCY[i], EC.N))
	}

	P := TwoVectorPCommitWithGens(EC.BPG, HPrime, left, right)
	//fmt.Println(P)

	MRPResult.IPP = InnerProductProve(left, right, that, P, EC.U, EC.BPG, HPrime)

	return MRPResult, Comms
}

/*
MultiRangeProof Verify
Takes in a MultiRangeProof and verifies its correctness

*/
func MRPVerify(mrp *MultiRangeProof, comms []ECPoint) bool {
	m := len(comms)
	bitsPerValue := EC.V / m

	//changes:
	// check 1 changes since it includes all commitments
	// check 2 commitment generation is also different

	// verify the challenges
	chal1s256 := sha256.Sum256([]byte(mrp.A.X.String() + mrp.A.Y.String()))
	cy := new(big.Int).SetBytes(chal1s256[:])

	chal2s256 := sha256.Sum256([]byte(mrp.S.X.String() + mrp.S.Y.String()))
	cz := new(big.Int).SetBytes(chal2s256[:])

	chal3s256 := sha256.Sum256([]byte(mrp.T1.X.String() + mrp.T1.Y.String() + mrp.T2.X.String() + mrp.T2.Y.String()))
	cx := new(big.Int).SetBytes(chal3s256[:])


	// given challenges are correct, very range proof
	PowersOfY := PowerVector(EC.V, cy)

	// t_hat * G + tau * H
	lhs := EC.G.Mult(mrp.Th).Add(EC.H.Mult(mrp.Tau))

	// z^2 * \bold{z}^m \bold{V} + delta(y,z) * G + x * T1 + x^2 * T2
	CommPowers := EC.Zero()
	PowersOfZ := PowerVector(m, cz)
	z2 := new(big.Int).Mod(new(big.Int).Mul(cz, cz), EC.N)

	for j := 0; j < m; j++ {
		CommPowers = CommPowers.Add(comms[j].Mult(new(big.Int).Mul(z2, PowersOfZ[j])))
	}

	rhs := EC.G.Mult(DeltaMRP(PowersOfY, cz, m)).Add(
		mrp.T1.Mult(cx)).Add(
		mrp.T2.Mult(new(big.Int).Mul(cx, cx))).Add(CommPowers)

	if !lhs.Equal(rhs) {
		fmt.Println("MRPVerify - Uh oh! Check line (63) of verification")
		fmt.Println(rhs)
		fmt.Println(lhs)
		return false
	}

	tmp1 := EC.Zero()
	zneg := new(big.Int).Mod(new(big.Int).Neg(cz), EC.N)
	for i := range EC.BPG {
		tmp1 = tmp1.Add(EC.BPG[i].Mult(zneg))
	}

	PowerOfTwos := PowerVector(bitsPerValue, big.NewInt(2))
	tmp2 := EC.Zero()
	// generate h'
	HPrime := make([]ECPoint, len(EC.BPH))

	for i := range HPrime {
		mi := new(big.Int).ModInverse(PowersOfY[i], EC.N)
		HPrime[i] = EC.BPH[i].Mult(mi)
	}

	for j := 0; j < m; j++ {
		for i := 0; i < bitsPerValue; i++ {
			val1 := new(big.Int).Mul(cz, PowersOfY[j*bitsPerValue+i])
			zp := new(big.Int).Exp(cz, big.NewInt(2+int64(j)), EC.N)
			val2 := new(big.Int).Mod(new(big.Int).Mul(zp, PowerOfTwos[i]), EC.N)
			tmp2 = tmp2.Add(HPrime[j*bitsPerValue+i].Mult(new(big.Int).Add(val1, val2)))
		}
	}

	// without subtracting this value should equal muCH + l[i]G[i] + r[i]H'[i]
	// we want to make sure that the innerproduct checks out, so we subtract it
	P := mrp.A.Add(mrp.S.Mult(cx)).Add(tmp1).Add(tmp2).Add(EC.H.Mult(mrp.Mu).Neg())
	//fmt.Println(P)

	if !InnerProductVerifyFast(mrp.Th, P, EC.U, EC.BPG, HPrime, mrp.IPP) {
		fmt.Println("MRPVerify - Uh oh! Check line (65) of verification!")
		return false
	}

	return true
}

// NewECPrimeGroupKey returns the curve (field),
// Generator 1 x&y, Generator 2 x&y, order of the generators
func NewECPrimeGroupKey(n int) CryptoParams {
	curValue := secp256k1.S256().Gx
	s256 := sha256.New()
	gen1Vals := make([]ECPoint, n)
	gen2Vals := make([]ECPoint, n)
	u := ECPoint{big.NewInt(0), big.NewInt(0)}
	cg := ECPoint{}
	ch := ECPoint{}

	j := 0
	confirmed := 0
	for confirmed < (2*n + 3) {
		s256.Write(new(big.Int).Add(curValue, big.NewInt(int64(j))).Bytes())

		potentialXValue := make([]byte, 33)
		binary.LittleEndian.PutUint32(potentialXValue, 2)
		for i, elem := range s256.Sum(nil) {
			potentialXValue[i+1] = elem
		}

		gen2, err := secp256k1.ParsePubKey(potentialXValue)
		if err == nil {
			if confirmed == 2*n { // once we've generated all g and h values then assign this to u
				u = ECPoint{gen2.X, gen2.Y}
				//fmt.Println("Got that U value")
			} else if confirmed == 2*n+1 {
				cg = ECPoint{gen2.X, gen2.Y}

			} else if confirmed == 2*n+2 {
				ch = ECPoint{gen2.X, gen2.Y}
			} else {
				if confirmed%2 == 0 {
					gen1Vals[confirmed/2] = ECPoint{gen2.X, gen2.Y}
					//fmt.Println("new G Value")
				} else {
					gen2Vals[confirmed/2] = ECPoint{gen2.X, gen2.Y}
					//fmt.Println("new H value")
				}
			}
			confirmed++
		}
		j++
	}

	return CryptoParams{
		secp256k1.S256(),
		secp256k1.S256(),
		gen1Vals,
		gen2Vals,
		secp256k1.S256().N,
		u,
		n,
		cg,
		ch}
}

func init() {
	EC = NewECPrimeGroupKey(VecLength)
	//fmt.Println(EC)
}
