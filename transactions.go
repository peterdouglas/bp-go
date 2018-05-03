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

func (mp *MultiRangeProof) Serialize() (string, error) {
	// create the protobuff object for serialization
	pbmp := &pb.MultiRangeProof{}
	/*for _, comm := range mp.Comms {
		newComm := &pb.Commitment{comm.EncValue, comm.Blind.Bytes(), comm.Comm.X.Bytes(), comm.Comm.Y.Bytes()}
		pbmp.Comm = append(pbmp.Comm, newComm)
	}*/

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

	for i := 0;i < len(mp.IPP.Challenges) ;i++  {
		pbmp.IPP.Challenges = append(pbmp.IPP.Challenges, mp.IPP.Challenges[i].Bytes())
	}

	pbmp.IPP.A = mp.IPP.A.Bytes()
	pbmp.IPP.B = mp.IPP.B.Bytes()
	pbmp.Cy = mp.Cy.Bytes()
	pbmp.Cz = mp.Cz.Bytes()
	pbmp.Cx = mp.Cx.Bytes()

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

	for i:= 0; i < len(pbRp.IPP.Challenges) ; i++  {
		tempChal := new(big.Int).SetBytes(pbRp.IPP.Challenges[i])
		mp.IPP.Challenges = append(mp.IPP.Challenges, tempChal)
	}

	mp.IPP.A = new(big.Int).SetBytes(pbRp.IPP.A)
	mp.IPP.B = new(big.Int).SetBytes(pbRp.IPP.B)
	mp.Cy = new(big.Int).SetBytes(pbRp.Cy)
	mp.Cz = new(big.Int).SetBytes(pbRp.Cz)
	mp.Cx = new(big.Int).SetBytes(pbRp.Cx)

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

	for i:= 0; i < len(pbRp.IPP.Challenges) ; i++  {
		tempChal:= new(big.Int).SetBytes(pbRp.IPP.Challenges[i])
		rp.IPP.Challenges = append(rp.IPP.Challenges, tempChal)
	}

	rp.IPP.A = new(big.Int).SetBytes(pbRp.IPP.A)
	rp.IPP.B = new(big.Int).SetBytes(pbRp.IPP.B)
	rp.Cy = new(big.Int).SetBytes(pbRp.Cy)
	rp.Cz = new(big.Int).SetBytes(pbRp.Cz)
	rp.Cx = new(big.Int).SetBytes(pbRp.Cx)

	return nil
}

func (rp *RangeProof) Verify(x, y *big.Int) bool {
	comm := ECPoint{x, y}
	return RPVerifyTrans(&comm, rp)
}

func (rp *RangeProof) Bytes() []byte {
	//var space = []byte(" ")
	var retBytes bytes.Buffer
	retBytes.Write(rp.A.Bytes())
	//retBytes.Write(space)
	retBytes.Write(rp.S.Bytes())
	//retBytes.Write(space)
	retBytes.Write(rp.T1.Bytes())
	//retBytes.Write(space)
	retBytes.Write(rp.T2.Bytes())
	//retBytes.Write(space)
	retBytes.Write(rp.Tau.Bytes())
	retBytes.Write(rp.Th.Bytes())
	//retBytes.Write(space)
	if len(rp.Th.Bytes()) != 32 {
		fmt.Printf("Tau %v\n", rp.Th.Sign())
	}
	//retBytes.Write(space)
	retBytes.Write(rp.Mu.Bytes())
	//retBytes.Write(space)

	// now for the IPP bytes
	for i :=0; i < len(rp.IPP.R);i++  {
		retBytes.Write(rp.IPP.L[i].Bytes())
		//retBytes.Write(space)
		retBytes.Write(rp.IPP.R[i].Bytes())
		//retBytes.Write(space)
	}
	retBytes.Write(rp.IPP.A.Bytes())
	//retBytes.Write(space)
	retBytes.Write(rp.IPP.B.Bytes())
	//retBytes.Write(space)

	for i := 0; i < len(rp.IPP.Challenges) ; i++  {
		retBytes.Write(rp.IPP.Challenges[i].Bytes())
		//retBytes.Write(space)
	}

	retBytes.Write(rp.Cy.Bytes())
	//retBytes.Write(space)
	retBytes.Write(rp.Cz.Bytes())
	//retBytes.Write(space)
	retBytes.Write(rp.Cx.Bytes())
	//retBytes.Write(space)
	return retBytes.Bytes()

}

func (rp *RangeProof) RebuildBytes(buf []byte)  {

	rebBytes := bytes.Fields(buf)
	rp.A.Rebuild(rebBytes[0])
	rp.S.Rebuild(rebBytes[1])
	rp.T1.Rebuild(rebBytes[2])
	rp.T2.Rebuild(rebBytes[3])

	rp.Tau = new(big.Int).SetBytes(rebBytes[4])
	rp.Th = new(big.Int).SetBytes(rebBytes[5])
	rp.Mu = new(big.Int).SetBytes(rebBytes[6])
	var j = 7
	rp.IPP.L = make([]ECPoint, 6)
	rp.IPP.R = make([]ECPoint, 6)
	for i := 0; i < 6; i++  {
		rp.IPP.L[i].Rebuild(rebBytes[j])
		j++
		rp.IPP.R[i].Rebuild(rebBytes[j])
		j++
	}

	rp.IPP.A = new(big.Int).SetBytes(rebBytes[j])
	j++
	rp.IPP.B = new(big.Int).SetBytes(rebBytes[j])
	j++
	rp.IPP.Challenges = make([]*big.Int, 7)
	for i := 0; i < 7;i++  {
		rp.IPP.Challenges[i] = new(big.Int).SetBytes(rebBytes[j])
		j++
	}

	rp.Cy = new(big.Int).SetBytes(rebBytes[j])
	j++
	rp.Cz = new(big.Int).SetBytes(rebBytes[j])
	j++
	rp.Cx = new(big.Int).SetBytes(rebBytes[j])

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

	for i := 0;i < len(rp.IPP.Challenges) ;i++  {
		pbrp.IPP.Challenges = append(pbrp.IPP.Challenges, rp.IPP.Challenges[i].Bytes())
	}

	pbrp.IPP.A = rp.IPP.A.Bytes()
	pbrp.IPP.B = rp.IPP.B.Bytes()
	pbrp.Cy = rp.Cy.Bytes()
	pbrp.Cz = rp.Cz.Bytes()
	pbrp.Cx = rp.Cx.Bytes()

	serialMp, err := proto.Marshal(pbrp)
	if err != nil {
		return "", err
	} else {
		fmt.Printf("The length of the range proof is %v\n", len(serialMp))
		return base58.Encode(serialMp), nil
	}
}
