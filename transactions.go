package bp_go

import (
	"math/big"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/decred/base58"
	"github.com/golang/protobuf/proto"
	"github.com/peterdouglas/bp-go/pb"
	"encoding/hex"
	"log"
	"crypto/sha256"
	"fmt"
	"bytes"
)

type Transaction struct {
	sender secp256k1.PublicKey
	value ECPoint
	blindingFactor big.Int
	reciver secp256k1.PublicKey
}

// Generate a single commitment from a commitment struct
func (c *Commitment) Generate(receiverKey *secp256k1.PublicKey, v, sSecret *big.Int)  error {
	hash := sha256.Sum256(v.Bytes())

	gamma := secp256k1.NonceRFC6979(sSecret, hash[:], nil, nil)
	c.Comm = EC.G.Mult(v).Add(EC.H.Mult(gamma))
	c.Blind = gamma
	// now we encrypt the value so the receiver can recreate the trans
	ciphertext, err := secp256k1.Encrypt(receiverKey, []byte(v.String()))
	if err != nil {
		return err
	}

	c.EncValue = ciphertext
	return nil
}


func (rp *MultiRangeProof) Bytes() []byte {
	var retBytes bytes.Buffer
	retBytes.Write(rp.A.Bytes())
	retBytes.Write(rp.S.Bytes())
	retBytes.Write(rp.T1.Bytes())
	retBytes.Write(rp.T2.Bytes())
	retBytes.Write(rp.Tau.Bytes())
	retBytes.Write(rp.Th.Bytes())
	if len(rp.Th.Bytes()) != 32 {
		fmt.Printf("Tau %v\n", rp.Th.Sign())
	}
	retBytes.Write(rp.Mu.Bytes())

	// now for the IPP bytes
	for i :=0; i < len(rp.IPP.R);i++  {
		retBytes.Write(rp.IPP.L[i].Bytes())
		retBytes.Write(rp.IPP.R[i].Bytes())
	}
	retBytes.Write(rp.IPP.A.Bytes())
	retBytes.Write(rp.IPP.B.Bytes())


	return retBytes.Bytes()

}

func (mp *MultiRangeProof) Serialize() (string, error) {
	// create the protobuff object for serialization
	pbmp := &pb.MultiRangeProof{}

	pbmp.A = &pb.ECPoint{mp.A.Bytes()}
	pbmp.S = &pb.ECPoint{mp.S.Bytes()}
	pbmp.T1 = &pb.ECPoint{mp.T1.Bytes()}
	pbmp.T2 = &pb.ECPoint{mp.T2.Bytes()}

	pbmp.Tau = mp.Tau.Bytes()
	pbmp.Th = mp.Th.Bytes()
	pbmp.Mu = mp.Mu.Bytes()

	pbmp.IPP = &pb.InnerProductProof{}
	
	for i := 0;i < len(mp.IPP.L) ;i++  {
		newIPL := &pb.ECPoint{mp.IPP.L[i].Bytes()}
		newIPR := &pb.ECPoint{mp.IPP.R[i].Bytes()}
		pbmp.IPP.L = append(pbmp.IPP.L, newIPL)
		pbmp.IPP.R = append(pbmp.IPP.R, newIPR)
	}


	pbmp.IPP.A = mp.IPP.A.Bytes()
	pbmp.IPP.B = mp.IPP.B.Bytes()

	serialMp, err := proto.Marshal(pbmp)
	if err != nil {
		return "", err
	} else {
		return base58.Encode(serialMp), nil
	}
}

func (mp *MultiRangeProof) Rebuild(encodedMP string) (error) {
	bRp, err := hex.DecodeString(encodedMP)
	if err != nil {
		return err
	}

	pbRp := &pb.MultiRangeProof{}

	if err := proto.Unmarshal(bRp, pbRp); err != nil {
		log.Fatalln("Failed to parse range proof:", err)
		return err
	}



	mp.A.Rebuild(pbRp.A.GetCompressed())
	mp.S.Rebuild(pbRp.S.GetCompressed())
	mp.T1.Rebuild(pbRp.T1.GetCompressed())
	mp.T2.Rebuild(pbRp.T2.GetCompressed())


	mp.Tau = new(big.Int).SetBytes(pbRp.Tau)
	mp.Th = new(big.Int).SetBytes(pbRp.Th)
	mp.Mu = new(big.Int).SetBytes(pbRp.Mu)


	mp.IPP = InnerProdArg{}

	for i := 0;i < len(pbRp.IPP.L) ;i++  {
		newIPL :=  ECPoint{}
		err := newIPL.Rebuild(pbRp.IPP.L[i].GetCompressed())
		if err != nil {
			log.Fatal(err)
		}
		newIPR :=  ECPoint{}
		err = newIPR.Rebuild(pbRp.IPP.R[i].GetCompressed())
		if err != nil {
			log.Fatal(err)
		}
		mp.IPP.L = append(mp.IPP.L, newIPL)
		mp.IPP.R = append(mp.IPP.R, newIPR)
	}


	mp.IPP.A = new(big.Int).SetBytes(pbRp.IPP.A)
	mp.IPP.B = new(big.Int).SetBytes(pbRp.IPP.B)

	return nil
}

func (rp *RangeProof) Rebuild(encodedRP string) (error) {
	bRp := base58.Decode(encodedRP)
	pbRp := &pb.RangeProof{}

	if err := proto.Unmarshal(bRp, pbRp); err != nil {
		log.Fatalln("Failed to parse range proof:", err)
		return err
	}


	rp.A.Rebuild(pbRp.A.GetCompressed())
	rp.S.Rebuild(pbRp.S.GetCompressed())
	rp.T1.Rebuild(pbRp.T1.GetCompressed())
	rp.T2.Rebuild(pbRp.T2.GetCompressed())


	rp.Tau = new(big.Int).SetBytes(pbRp.Tau)
	rp.Th = new(big.Int).SetBytes(pbRp.Th)
	rp.Mu = new(big.Int).SetBytes(pbRp.Mu)


	rp.IPP = InnerProdArg{}

	for i := 0;i < len(pbRp.IPP.L) ;i++  {
		newIPL :=  ECPoint{}
		err := newIPL.Rebuild(pbRp.IPP.L[i].GetCompressed())
		if err != nil {
			log.Fatal(err)
		}

		newIPR :=  ECPoint{}
		err = newIPR.Rebuild(pbRp.IPP.R[i].GetCompressed())
		if err != nil {
			log.Fatal(err)
		}
		rp.IPP.L = append(rp.IPP.L, newIPL)
		rp.IPP.R = append(rp.IPP.R, newIPR)
	}

	rp.IPP.A = new(big.Int).SetBytes(pbRp.IPP.A)
	rp.IPP.B = new(big.Int).SetBytes(pbRp.IPP.B)

	return nil
}

func (rp *RangeProof) Verify(x, y *big.Int) bool {
	comm := ECPoint{x, y}
	return RPVerifyTrans(&comm, rp)
}

func (rp *RangeProof) Bytes() []byte {
	var retBytes bytes.Buffer
	retBytes.Write(rp.A.Bytes())
	retBytes.Write(rp.S.Bytes())
	retBytes.Write(rp.T1.Bytes())
	retBytes.Write(rp.T2.Bytes())
	retBytes.Write(rp.Tau.Bytes())
	retBytes.Write(rp.Th.Bytes())

	retBytes.Write(rp.Mu.Bytes())

	// now for the IPP bytes
	for i :=0; i < len(rp.IPP.R);i++  {
		retBytes.Write(rp.IPP.L[i].Bytes())
		retBytes.Write(rp.IPP.R[i].Bytes())
	}
	retBytes.Write(rp.IPP.A.Bytes())
	retBytes.Write(rp.IPP.B.Bytes())


	return retBytes.Bytes()

}

func (rp *RangeProof) Serialize() (string, error) {
	// create the protobuff object for serialization
	pbrp := &pb.RangeProof{}

	pbrp.A = &pb.ECPoint{rp.A.Bytes()}
	pbrp.S = &pb.ECPoint{rp.S.Bytes()}
	pbrp.T1 = &pb.ECPoint{rp.T1.Bytes()}
	pbrp.T2 = &pb.ECPoint{rp.T2.Bytes()}

	pbrp.Tau = rp.Tau.Bytes()
	pbrp.Th = rp.Th.Bytes()
	pbrp.Mu = rp.Mu.Bytes()

	pbrp.IPP = &pb.InnerProductProof{}

	for i := 0;i < len(rp.IPP.L) ;i++  {
		newIPL := &pb.ECPoint{rp.IPP.L[i].Bytes()}
		newIPR := &pb.ECPoint{rp.IPP.R[i].Bytes()}
		pbrp.IPP.L = append(pbrp.IPP.L, newIPL)
		pbrp.IPP.R = append(pbrp.IPP.R, newIPR)
	}


	pbrp.IPP.A = rp.IPP.A.Bytes()
	pbrp.IPP.B = rp.IPP.B.Bytes()

	serialMp, err := proto.Marshal(pbrp)
	if err != nil {
		return "", err
	} else {
		return base58.Encode(serialMp), nil
	}
}

