package bp_go

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/davecgh/go-spew/spew"
	"os"
	"bytes"
	"encoding/gob"
	"log"
)

func TestInnerProductProveLen1(t *testing.T) {
	fmt.Println("TestInnerProductProve1")
	EC = NewECPrimeGroupKey(1)
	a := make([]*big.Int, 1)
	b := make([]*big.Int, 1)

	a[0] = big.NewInt(2)

	b[0] = big.NewInt(-4)

	c := InnerProduct(a, b)

	P := TwoVectorPCommitWithGens(EC.BPG, EC.BPH, a, b)

	ipp := InnerProductProve(a, b, c, P, EC.U, EC.BPG, EC.BPH)

	if InnerProductVerify(c, P, EC.U, EC.BPG, EC.BPH, ipp) {
		fmt.Println("Inner Product Proof correct")
	} else {
		t.Error("Inner Product Proof incorrect")
	}
}

func TestInnerProductProveLen2(t *testing.T) {
	fmt.Println("TestInnerProductProve2")
	EC = NewECPrimeGroupKey(2)
	a := make([]*big.Int, 2)
	b := make([]*big.Int, 2)

	a[0] = big.NewInt(2)
	a[1] = big.NewInt(3)

	b[0] = big.NewInt(2)
	b[1] = big.NewInt(3)

	c := InnerProduct(a, b)

	P := TwoVectorPCommitWithGens(EC.BPG, EC.BPH, a, b)

	ipp := InnerProductProve(a, b, c, P, EC.U, EC.BPG, EC.BPH)

	if InnerProductVerify(c, P, EC.U, EC.BPG, EC.BPH, ipp) {
		fmt.Println("Inner Product Proof correct")
	} else {
		t.Error("Inner Product Proof incorrect")
	}
}

func TestInnerProductProveLen4(t *testing.T) {
	fmt.Println("TestInnerProductProve4")
	EC = NewECPrimeGroupKey(4)
	a := make([]*big.Int, 4)
	b := make([]*big.Int, 4)

	a[0] = big.NewInt(1)
	a[1] = big.NewInt(1)
	a[2] = big.NewInt(1)
	a[3] = big.NewInt(1)

	b[0] = big.NewInt(1)
	b[1] = big.NewInt(1)
	b[2] = big.NewInt(1)
	b[3] = big.NewInt(1)

	c := InnerProduct(a, b)

	P := TwoVectorPCommitWithGens(EC.BPG, EC.BPH, a, b)

	ipp := InnerProductProve(a, b, c, P, EC.U, EC.BPG, EC.BPH)

	if InnerProductVerify(c, P, EC.U, EC.BPG, EC.BPH, ipp) {
		fmt.Println("Inner Product Proof correct")
	} else {
		t.Error("Inner Product Proof incorrect")
	}
}

func TestInnerProductProveLen8(t *testing.T) {
	fmt.Println("TestInnerProductProve8")
	EC = NewECPrimeGroupKey(8)
	a := make([]*big.Int, 8)
	b := make([]*big.Int, 8)

	a[0] = big.NewInt(1)
	a[1] = big.NewInt(1)
	a[2] = big.NewInt(1)
	a[3] = big.NewInt(1)
	a[4] = big.NewInt(1)
	a[5] = big.NewInt(1)
	a[6] = big.NewInt(1)
	a[7] = big.NewInt(1)

	b[0] = big.NewInt(2)
	b[1] = big.NewInt(2)
	b[2] = big.NewInt(2)
	b[3] = big.NewInt(2)
	b[4] = big.NewInt(2)
	b[5] = big.NewInt(2)
	b[6] = big.NewInt(2)
	b[7] = big.NewInt(2)

	c := InnerProduct(a, b)

	P := TwoVectorPCommitWithGens(EC.BPG, EC.BPH, a, b)

	ipp := InnerProductProve(a, b, c, P, EC.U, EC.BPG, EC.BPH)

	if InnerProductVerify(c, P, EC.U, EC.BPG, EC.BPH, ipp) {
		fmt.Println("Inner Product Proof correct")
	} else {
		t.Error("Inner Product Proof incorrect")
	}
}

func TestInnerProductProveLen64Rand(t *testing.T) {
	fmt.Println("TestInnerProductProveLen64Rand")
	EC = NewECPrimeGroupKey(64)
	a := RandVector(64)
	b := RandVector(64)

	c := InnerProduct(a, b)

	P := TwoVectorPCommitWithGens(EC.BPG, EC.BPH, a, b)

	ipp := InnerProductProve(a, b, c, P, EC.U, EC.BPG, EC.BPH)

	if InnerProductVerify(c, P, EC.U, EC.BPG, EC.BPH, ipp) {
		fmt.Println("Inner Product Proof correct")
	} else {
		t.Error("Inner Product Proof incorrect")
		fmt.Printf("Values Used: \n\ta = %s\n\tb = %s\n", a, b)
	}

}

func TestInnerProductVerifyFastLen1(t *testing.T) {
	fmt.Println("TestInnerProductProve1")
	EC = NewECPrimeGroupKey(1)
	a := make([]*big.Int, 1)
	b := make([]*big.Int, 1)

	a[0] = big.NewInt(2)

	b[0] = big.NewInt(2)

	c := InnerProduct(a, b)

	P := TwoVectorPCommitWithGens(EC.BPG, EC.BPH, a, b)

	ipp := InnerProductProve(a, b, c, P, EC.U, EC.BPG, EC.BPH)

	if InnerProductVerifyFast(c, P, EC.U, EC.BPG, EC.BPH, ipp) {
		fmt.Println("Inner Product Proof correct")
	} else {
		t.Error("Inner Product Proof incorrect")
	}
}

func TestInnerProductVerifyFastLen2(t *testing.T) {
	fmt.Println("TestInnerProductProve2")
	EC = NewECPrimeGroupKey(2)
	a := make([]*big.Int, 2)
	b := make([]*big.Int, 2)

	a[0] = big.NewInt(2)
	a[1] = big.NewInt(3)

	b[0] = big.NewInt(2)
	b[1] = big.NewInt(3)

	c := InnerProduct(a, b)

	P := TwoVectorPCommitWithGens(EC.BPG, EC.BPH, a, b)

	ipp := InnerProductProve(a, b, c, P, EC.U, EC.BPG, EC.BPH)

	if InnerProductVerifyFast(c, P, EC.U, EC.BPG, EC.BPH, ipp) {
		fmt.Println("Inner Product Proof correct")
	} else {
		t.Error("Inner Product Proof incorrect")
	}
}

func TestInnerProductVerifyFastLen4(t *testing.T) {
	fmt.Println("TestInnerProductProve4")
	EC = NewECPrimeGroupKey(4)
	a := make([]*big.Int, 4)
	b := make([]*big.Int, 4)

	a[0] = big.NewInt(1)
	a[1] = big.NewInt(1)
	a[2] = big.NewInt(1)
	a[3] = big.NewInt(1)

	b[0] = big.NewInt(1)
	b[1] = big.NewInt(1)
	b[2] = big.NewInt(1)
	b[3] = big.NewInt(1)

	c := InnerProduct(a, b)

	P := TwoVectorPCommitWithGens(EC.BPG, EC.BPH, a, b)

	ipp := InnerProductProve(a, b, c, P, EC.U, EC.BPG, EC.BPH)

	if InnerProductVerifyFast(c, P, EC.U, EC.BPG, EC.BPH, ipp) {
		fmt.Println("Inner Product Proof correct")
	} else {
		t.Error("Inner Product Proof incorrect")
	}
}

func TestInnerProductVerifyFastLen8(t *testing.T) {
	fmt.Println("TestInnerProductProve8")
	EC = NewECPrimeGroupKey(8)
	a := make([]*big.Int, 8)
	b := make([]*big.Int, 8)

	a[0] = big.NewInt(1)
	a[1] = big.NewInt(1)
	a[2] = big.NewInt(1)
	a[3] = big.NewInt(1)
	a[4] = big.NewInt(1)
	a[5] = big.NewInt(1)
	a[6] = big.NewInt(1)
	a[7] = big.NewInt(1)

	b[0] = big.NewInt(2)
	b[1] = big.NewInt(2)
	b[2] = big.NewInt(2)
	b[3] = big.NewInt(2)
	b[4] = big.NewInt(2)
	b[5] = big.NewInt(2)
	b[6] = big.NewInt(2)
	b[7] = big.NewInt(2)

	c := InnerProduct(a, b)

	P := TwoVectorPCommitWithGens(EC.BPG, EC.BPH, a, b)

	ipp := InnerProductProve(a, b, c, P, EC.U, EC.BPG, EC.BPH)

	if InnerProductVerifyFast(c, P, EC.U, EC.BPG, EC.BPH, ipp) {
		fmt.Println("Inner Product Proof correct")
	} else {
		t.Error("Inner Product Proof incorrect")
	}
}

func TestInnerProductVerifyFastLen64Rand(t *testing.T) {
	fmt.Println("TestInnerProductProveLen64Rand")
	EC = NewECPrimeGroupKey(64)
	a := RandVector(64)
	b := RandVector(64)

	c := InnerProduct(a, b)

	P := TwoVectorPCommitWithGens(EC.BPG, EC.BPH, a, b)

	ipp := InnerProductProve(a, b, c, P, EC.U, EC.BPG, EC.BPH)

	if InnerProductVerifyFast(c, P, EC.U, EC.BPG, EC.BPH, ipp) {
		fmt.Println("Inner Product Proof correct")
	} else {
		t.Error("Inner Product Proof incorrect")
		fmt.Printf("Values Used: \n\ta = %s\n\tb = %s\n", a, b)
	}

}

func TestValueBreakdown(t *testing.T) {
	v := big.NewInt(20)
	yes := reverse(StrToBigIntArray(PadLeft(fmt.Sprintf("%b", v), "0", 64)))
	vec2 := PowerVector(64, big.NewInt(2))

	calc := InnerProduct(yes, vec2)
	spew.Dump(yes)

	if v.Cmp(calc) != 0 {
		t.Error("Binary Value Breakdown - Failure :(")
		fmt.Println(yes)
		fmt.Println(vec2)
		fmt.Println(calc)
	} else {
		fmt.Println("Binary Value Breakdown - Success!")
		fmt.Println(yes)
		fmt.Println(vec2)
		fmt.Println(calc)
	}
}

func TestValueBreakdownRand(t *testing.T) {
	v, err := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(64), EC.N))
	check(err)

	yes := reverse(StrToBigIntArray(PadLeft(fmt.Sprintf("%b", v), "0", 64)))
	vec2 := PowerVector(64, big.NewInt(2))

	calc := InnerProduct(yes, vec2)

	if v.Cmp(calc) != 0 {
		t.Error("Binary Value Breakdown - Failure :(")
		fmt.Println(yes)
		fmt.Println(vec2)
		fmt.Println(calc)
	} else {
		fmt.Println("Binary Value Breakdown - Success!")
	}

}

func TestVectorHadamard(t *testing.T) {
	a := make([]*big.Int, 5)
	a[0] = big.NewInt(1)
	a[1] = big.NewInt(1)
	a[2] = big.NewInt(1)
	a[3] = big.NewInt(1)
	a[4] = big.NewInt(1)

	c := VectorHadamard(a, a)

	success := true

	for i := range c {
		if c[i].Cmp(a[i]) != 0 {
			success = false
		}
	}
	if !success {
		t.Error("Failure in the Hadamard")
	} else {
		fmt.Println("Hadamard good")
	}
}

var (
	aliceSK *secp256k1.PrivateKey
	bobSK *secp256k1.PrivateKey
	alicePk *secp256k1.PublicKey
	bobPk *secp256k1.PublicKey
)

func TestMain(m *testing.M) {
	// create the private keys
	aliceSK, _ = secp256k1.GeneratePrivateKey()
	bobSK, _ = secp256k1.GeneratePrivateKey()

	// gen public keys
	alicePkx, alicePky := aliceSK.Public()
	bobPkx, bobPky := bobSK.Public()

	alicePk = secp256k1.NewPublicKey(alicePkx, alicePky)
	bobPk = secp256k1.NewPublicKey(bobPkx, bobPky)

	os.Exit(m.Run())
}


func TestMRPVerifyTransWithReceiverConf(t *testing.T) {
	EC = NewECPrimeGroupKey(64)


	valArr := make([]*big.Int, 4)
	valArr[0] = big.NewInt(6)
	valArr[1] = big.NewInt(7)
	valArr[2] = big.NewInt(4)
	valArr[3] = big.NewInt(0)

    commitments, mrp := MRPProve(valArr)
	strMP, _ := mrp.Serialize()
	//strconv.Atoi(strMP)
	if MRPVerify(&mrp, commitments) {
		fmt.Println("Range Proof Verification works")
	} else {
		t.Error("*****Range Proof FAILURE")
	}

	f, _ := os.Create("./mrp_file.txt")
		defer f.Close()

		spew.Fdump(f, strMP)


}

func TestRPVerifyTransWithReceiverConf(t *testing.T) {
	EC = NewECPrimeGroupKey(64)
	// create the private keys
	aliceSK, _ := secp256k1.GeneratePrivateKey()
	bobSK, _ := secp256k1.GeneratePrivateKey()

	// gen public keys
	bobPkx, bobPky := bobSK.Public()

	val := big.NewInt(1779530283000000)

	bobPk := secp256k1.NewPublicKey(bobPkx, bobPky)

	// first we generate the shared secret
	sharedSec := secp256k1.GenerateSharedSecret(aliceSK, bobPk)
	secInt := new(big.Int)
	secInt.SetBytes(sharedSec)
	comm1 := new(Commitment)
	err := comm1.Generate(bobPk, val, secInt)
	if err != nil {
		t.Error(err)
	}
	rp := RPProveTrans(comm1.Blind, val)
	rpBytes := rp.Bytes()
	fmt.Printf("Byte length is %v\n", len(rpBytes))
	serRP, _ := rp.Serialize()
	//strT := GetRPTrytes(serRP)
	fmt.Printf("The length of the serialized range proof in bytes is %v\n", len([]byte(serRP)))
	rpb := &RangeProof{}

	fmt.Printf("%v\nThe length of the proof in Trytes is %v\n", serRP, len(serRP))
	rpb.Rebuild(serRP)
	if RPVerifyTrans(&comm1.Comm, rpb) {
		fmt.Println("Range Proof Verification works")
	} else {
		t.Error("*****Range Proof FAILURE")
	}

	f, _ := os.Create("./rp_file.txt")
	defer f.Close()

	spew.Fdump(f, serRP)


}

func TestRangeProof_Bytes(t *testing.T) {
	EC = NewECPrimeGroupKey(64)
	// create the private keys
	aliceSK, _ := secp256k1.GeneratePrivateKey()
	bobSK, _ := secp256k1.GeneratePrivateKey()

	// gen public keys
	bobPkx, bobPky := bobSK.Public()
	for i := 1; i <  1779530283000000; i = i*2 {

		val := big.NewInt(int64(i))

		bobPk := secp256k1.NewPublicKey(bobPkx, bobPky)

		// first we generate the shared secret
		sharedSec := secp256k1.GenerateSharedSecret(aliceSK, bobPk)
		secInt := new(big.Int)
		secInt.SetBytes(sharedSec)
		comm1 := new(Commitment)
		err := comm1.Generate(bobPk, val, secInt)
		if err != nil {
			t.Error(err)
		}
		rp := RPProveTrans(comm1.Blind, val)
		rpBytes, _ := rp.Serialize()
		/*if len(rp.Bytes()) != 1008 {
			spew.Dump(rp)
			break
		}*/
		fmt.Printf("Byte length for %v is %v\n",i, len(rpBytes))
	}
}

// Test using Gob to encode/decode instead of protobuf
func TestRangeProof_BytesFunc(t *testing.T) {
	EC = NewECPrimeGroupKey(64)
	// create the private keys
	aliceSK, _ := secp256k1.GeneratePrivateKey()
	bobSK, _ := secp256k1.GeneratePrivateKey()

	// gen public keys
	bobPkx, bobPky := bobSK.Public()

	val := big.NewInt(10000090000)

	bobPk := secp256k1.NewPublicKey(bobPkx, bobPky)

	// first we generate the shared secret
	sharedSec := secp256k1.GenerateSharedSecret(aliceSK, bobPk)
	secInt := new(big.Int)
	secInt.SetBytes(sharedSec)
	comm1 := new(Commitment)
	err := comm1.Generate(bobPk, val, secInt)
	if err != nil {
		t.Error(err)
	}
	rp := RPProveTrans(comm1.Blind, val)
	var network bytes.Buffer
	enc := gob.NewEncoder(&network)
	dec := gob.NewDecoder(&network)
	err = enc.Encode(rp)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("The length is %v\n", network.Len())
	var rebRp RangeProof
	err = dec.Decode(&rebRp)
	if err != nil {
		t.Error(err)
	}

	//rebuiltRp := &RangeProof{}
	//rebuiltRp.RebuildBytes(rpBytes)

	if RPVerifyTrans(&comm1.Comm, &rebRp) {
		fmt.Println("Range Proof Verification works")
	} else {
	t.Error("*****Range Proof FAILURE")
	}
}

func TestRangeProofMax(t *testing.T) {
	for i := 1; i <= 128; i ++ {
		EC = NewECPrimeGroupKey(i)
		maxVal := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(EC.V)), EC.N)
		//fmt.Printf("The max val for %v is %v\n", i, maxVal)
		if maxVal.Cmp(big.NewInt(1779530283000000)) >= 1 {
			fmt.Printf("The mimimum is %v\n", i)
			break;
		}
	}
}


func TestRPVerify2(t *testing.T) {
	EC = NewECPrimeGroupKey(64)
	// Testing largest number in range
	if RPVerify(RPProve(new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(63), EC.N), big.NewInt(1)))) {
		fmt.Println("Range Proof Verification works")
	} else {
		t.Error("*****Range Proof FAILURE")
	}
}


func TestRPVerify3(t *testing.T) {
	EC = NewECPrimeGroupKey(64)
	// Testing the value 3
	if RPVerify(RPProve(big.NewInt(3))) {
		fmt.Println("Range Proof Verification works")
	} else {
		t.Error("*****Range Proof FAILURE")
	}
}


func TestRPVerify4(t *testing.T) {
	EC = NewECPrimeGroupKey(32)
	// Testing smallest number in range
	if RPVerify(RPProve(big.NewInt(0))) {
		fmt.Println("Range Proof Verification works")
	} else {
		t.Error("*****Range Proof FAILURE")
	}
}

func TestRPVerifyRand(t *testing.T) {
	EC = NewECPrimeGroupKey(64)

	ran, err := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(2), big.NewInt(64), EC.N))
	check(err)

	// Testing the value 3
	if RPVerify(RPProve(ran)) {
		fmt.Println("Range Proof Verification works")
	} else {
		t.Error("*****Range Proof FAILURE")
		fmt.Printf("Random Value: %s", ran.String())
	}
}


func TestMultiRPVerify1(t *testing.T) {
	values := []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)}
	EC = NewECPrimeGroupKey(64 * len(values))
	// Testing smallest number in range
	comms, proof := MRPProve(values)
	proofString := fmt.Sprintf("%s", proof)

	fmt.Println(len(proofString)) // length is good measure of bytes, correct?

	if MRPVerify(&proof, comms) {
		fmt.Println("Multi Range Proof Verification works")
	} else {
		t.Error("***** Multi Range Proof FAILURE")
	}
}

func TestMultiRPVerify2(t *testing.T) {
	values := []*big.Int{big.NewInt(0)}
	EC = NewECPrimeGroupKey(64 * len(values))
	// Testing smallest number in range
	comms, proof := MRPProve(values)

	if MRPVerify(&proof, comms) {
		fmt.Println("Multi Range Proof Verification works")
	} else {
		t.Error("***** Multi Range Proof FAILURE")
	}
}

func TestMultiRPVerify3(t *testing.T) {
	values := []*big.Int{big.NewInt(0), big.NewInt(1)}
	EC = NewECPrimeGroupKey(64 * len(values))
	// Testing smallest number in range
    comms, proof := MRPProve(values)

    if MRPVerify(&proof, comms) {
		fmt.Println("Multi Range Proof Verification works")
	} else {
		t.Error("***** Multi Range Proof FAILURE")
	}
}


//Still need to add testing for just the MPProve module without the components
func TestMultiRPVerify4(t *testing.T) {
	for j := 1; j < 33; j = 2 * j {
		values := make([]*big.Int, j)
		for k := 0; k < j; k++ {
			values[k] = big.NewInt(0)
		}

		EC = NewECPrimeGroupKey(64 * len(values))
		// Testing smallest number in range
		comms, proof := MRPProve(values)
		proofString := fmt.Sprintf("%s", proof)

		fmt.Println(len(proofString)) // length is good measure of bytes, correct?


        if MRPVerify(&proof, comms) {
			fmt.Println("Multi Range Proof Verification works")
		} else {
			t.Error("***** Multi Range Proof FAILURE")
		}
	}
}

func TestInnerProduct(t *testing.T) {
	fmt.Println("TestInnerProduct")
	a := make([]*big.Int, 4)
	b := make([]*big.Int, 4)

	a[0] = big.NewInt(2)
	a[1] = big.NewInt(2)
	a[2] = big.NewInt(2)
	a[3] = big.NewInt(2)

	b[0] = big.NewInt(2)
	b[1] = big.NewInt(2)
	b[2] = big.NewInt(2)
	b[3] = big.NewInt(2)

	c := InnerProduct(a, b)

	if c.Cmp(big.NewInt(16)) == 0 {
		fmt.Println("Success - Innerproduct works with 2")
	} else {
		t.Error("Failure - Innerproduct equal to ")
		fmt.Println(c.String())
	}

}


func BenchmarkMRPVerifySize(b *testing.B) {
	for i := 0; i < b.N; i++{
		for j := 1; j < 257; j*=2 {
			values := make([]*big.Int, j)
			for k := 0; k < j; k++{
				values[k] = big.NewInt(0)
			}

			EC = NewECPrimeGroupKey(64 * len(values))
			// Testing smallest number in range
			comms, proof := MRPProve(values)
			proofBytes := proof.Bytes()
			fmt.Printf("Size for %d values: %d bytes\n", j, len(proofBytes)) // length is good measure of bytes, correct?

            if MRPVerify(&proof, comms) {
				fmt.Println("Multi Range Proof Verification works")
			} else {
				fmt.Println("***** Multi Range Proof FAILURE")
			}
		}
	}
}

var result MultiRangeProof
var boores bool

func BenchmarkMRPProve16(b *testing.B) {
	j := 16
	values := make([]*big.Int, j)
	for k := 0; k < j; k++{
		values[k] = big.NewInt(0)
	}
	EC = NewECPrimeGroupKey(64 * len(values))
	var r MultiRangeProof
	for i := 0; i < b.N; i++{
		_, r = MRPProve(values)
	}

	result = r
}

func BenchmarkMRPVerify16(b *testing.B) {
	j := 16
	values := make([]*big.Int, j)
	for k := 0; k < j; k++{
		values[k] = big.NewInt(0)
	}
	EC = NewECPrimeGroupKey(64 * len(values))
	comms, proof := MRPProve(values)

	var r bool
	for i := 0; i < b.N; i++{
		r = MRPVerify(&proof, comms)
	}
	boores = r
}

func BenchmarkMRPProve32(b *testing.B) {
	j := 32
	values := make([]*big.Int, j)
	for k := 0; k < j; k++{
		values[k] = big.NewInt(0)
	}
	EC = NewECPrimeGroupKey(64 * len(values))
	var r MultiRangeProof
	for i := 0; i < b.N; i++{
		_, r = MRPProve(values)
	}
	result = r
}

func BenchmarkMRPVerify32(b *testing.B) {
	j := 32
	values := make([]*big.Int, j)
	for k := 0; k < j; k++{
		values[k] = big.NewInt(0)
	}
	EC = NewECPrimeGroupKey(64 * len(values))
    comms, proof := MRPProve(values)

	var r bool
	for i := 0; i < b.N; i++{
		r = MRPVerify(&proof, comms)
	}
	boores = r
}

