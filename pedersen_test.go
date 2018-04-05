package bulletproofs

import (
	"crypto/sha256"
	"fmt"
	"log"
	"math/big"
	"reflect"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/ethereum/go-ethereum/common"
)

func checkErr(err error) {
	if err != nil {
		log.Printf("there was an error %s", err)
	}
}

func TestCommitments(t *testing.T) {
	privKey, err := secp256k1.GeneratePrivateKey()
	checkErr(err)

	hash := sha256.Sum256([]byte("6"))

	cryptoNonce := common.Bytes2Hex(secp256k1.NonceRFC6979(privKey.D, hash[:], nil, nil).Bytes())

	fmt.Println(cryptoNonce)
}

func TestVectorPCommit(t *testing.T) {
	fmt.Println("TestVectorPCommit3")
	EC = NewECPrimeGroupKey(3)

	v := make([]*big.Int, 3)
	for j := range v {
		v[j] = big.NewInt(2)
	}

	output, r := VectorPCommit(v)
	fmt.Println(fmt.Sprintf("output is %s", output))
	fmt.Println(fmt.Sprintf("r is %s", r))
	if len(r) != 3 {
		fmt.Println("Failure - rvalues doesn't match length of values")
	}
	// we will verify correctness by replicating locally and comparing output

	GVal := EC.BPG[0].Mult(v[0]).Add(EC.BPG[1].Mult(v[1]).Add(EC.BPG[2].Mult(v[2])))
	HVal := EC.BPH[0].Mult(r[0]).Add(EC.BPH[1].Mult(r[1]).Add(EC.BPH[2].Mult(r[2])))
	Comm := GVal.Add(HVal)

	if output.Equal(Comm) {
		fmt.Println("Commitment correct")
	} else {
		t.Error("Commitment failed")
	}
}

func TestTwoVectorPCommit(t *testing.T) {
	fmt.Println("TestTwoVectorPCommit")
	EC = NewECPrimeGroupKey(1)

	v := make([]*big.Int, 1)
	for j := range v {
		v[j] = big.NewInt(2)
	}

	v2 := make([]*big.Int, 1)
	for j := range v2 {
		v2[j] = big.NewInt(6)
	}

	output := TwoVectorPCommit(v, v2)
	fmt.Println(fmt.Sprintf("output is %s", output))

	if !EC.C.IsOnCurve(output.X, output.Y) {
		fmt.Println("Failure - commit is not on curve")
	}
	// Need to determine how to verify this

}

func TestTwoVectorPCommitWithGens(t *testing.T) {
	type args struct {
		G []ECPoint
		H []ECPoint
		a []*big.Int
		b []*big.Int
	}
	tests := []struct {
		name string
		args args
		want ECPoint
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TwoVectorPCommitWithGens(tt.args.G, tt.args.H, tt.args.a, tt.args.b); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TwoVectorPCommitWithGens() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVectorPCommitTrans(t *testing.T) {
	type args struct {
		pubkey  *secp256k1.PublicKey
		value   []*big.Int
		sSecret *big.Int
	}
	tests := []struct {
		name  string
		args  args
		want  ECPoint
		want1 []*big.Int
		want2 [][]byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, got2 := VectorPCommitTrans(tt.args.pubkey, tt.args.value, tt.args.sSecret)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("VectorPCommitTrans() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("VectorPCommitTrans() got1 = %v, want %v", got1, tt.want1)
			}
			if !reflect.DeepEqual(got2, tt.want2) {
				t.Errorf("VectorPCommitTrans() got2 = %v, want %v", got2, tt.want2)
			}
		})
	}
}

