package bulletproofs

import (
	"math/big"
	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/golang/protobuf/proto"
	"github.com/peterdouglas/bp-go/pb"
	"encoding/hex"
	"log"
	"errors"
)



type Transaction struct {
	sender secp256k1.PublicKey
	value ECPoint
	blindingFactor big.Int
	reciver secp256k1.PublicKey
}

func PrepareTransaction(senderKey *secp256k1.PrivateKey, receiverKey, senderPubKey *secp256k1.PublicKey,  inputs []*big.Int) (MultiRangeProof) {
	// first we generate the shared secret
	sharedSec := secp256k1.GenerateSharedSecret(senderKey, receiverKey)
	secInt := new(big.Int)
	secInt.SetBytes(sharedSec)

	return MRPProveTrans(senderPubKey, inputs, secInt)

}

func (mp *MultiRangeProof) serialize() (string, error) {
	// create the protobuff object for serialization
	pbmp := &pb.MultiRangeProof{}
	for _, comm := range mp.Comms {
		newComm := &pb.Commitment{comm.EncValue, comm.Blind.Bytes(), comm.Comm.X.Bytes(), comm.Comm.Y.Bytes()}
		pbmp.Comm = append(pbmp.Comm, newComm)
	}

	pbmp.A = &pb.ECPoint{mp.A.X.Bytes(), mp.A.Y.Bytes()}
	pbmp.S = &pb.ECPoint{mp.S.X.Bytes(), mp.S.Y.Bytes()}
	pbmp.T1 = &pb.ECPoint{mp.T1.X.Bytes(), mp.T1.Y.Bytes()}
	pbmp.T2 = &pb.ECPoint{mp.T2.X.Bytes(), mp.T2.Y.Bytes()}

	for i := 0;i < len(mp.BPG) ;i++  {
		newBH := &pb.ECPoint{mp.BPG[i].X.Bytes(), mp.BPG[i].Y.Bytes()}
		newBG := &pb.ECPoint{mp.BPH[i].X.Bytes(), mp.BPH[i].Y.Bytes()}
		pbmp.BPG = append(pbmp.BPG, newBG)
		pbmp.BPH = append(pbmp.BPH, newBH)
	}

	pbmp.Tau = mp.Tau.String()
	pbmp.Th = mp.Th.String()
	pbmp.Mu = mp.Mu.String()

	pbmp.IPP = &pb.InnerProductProof{}
	
	for i := 0;i < len(mp.IPP.L) ;i++  {
		newIPL := &pb.ECPoint{mp.IPP.L[i].X.Bytes(), mp.IPP.L[i].Y.Bytes()}
		newIPR := &pb.ECPoint{mp.IPP.R[i].X.Bytes(), mp.IPP.R[i].Y.Bytes()}
		pbmp.IPP.L = append(pbmp.IPP.L, newIPL)
		pbmp.IPP.R = append(pbmp.IPP.R, newIPR)
	}

	for i := 0;i < len(mp.IPP.Challenges) ;i++  {
		pbmp.IPP.Challenges = append(pbmp.IPP.Challenges, mp.IPP.Challenges[i].String())
	}

	pbmp.IPP.A = mp.IPP.A.String()
	pbmp.IPP.B = mp.IPP.B.String()
	pbmp.Cy = mp.Cy.String()
	pbmp.Cz = mp.Cz.String()
	pbmp.Cx = mp.Cx.String()

	serialMp, err := proto.Marshal(pbmp)
	if err != nil {
		return "", err
	} else {
		return hex.EncodeToString(serialMp), nil
	}
}

func (mp *MultiRangeProof) rebuild(encodedMP string) (error) {
	bRp, err := hex.DecodeString(encodedMP)
	if err != nil {
		return err
	}

	pbRp := &pb.MultiRangeProof{}

	if err := proto.Unmarshal(bRp, pbRp); err != nil {
		log.Fatalln("Failed to parse range proof:", err)
		return err
	}


	for _, comm := range pbRp.Comm {
		var (
			x1 big.Int
			y1 big.Int
			b1 big.Int
		)
		newComm := Commitment{ECPoint{x1.SetBytes(comm.X), y1.SetBytes(comm.Y)}, comm.EncValue,  b1.SetBytes(comm.Blind)}
		mp.Comms = append(mp.Comms, newComm)
	}

	var (

		ok bool = true
	)

	mp.A = ECPoint{new(big.Int).SetBytes(pbRp.A.X),new(big.Int).SetBytes(pbRp.A.Y)}
	mp.S = ECPoint{new(big.Int).SetBytes(pbRp.S.X),new(big.Int).SetBytes(pbRp.S.Y)}
	mp.T1 = ECPoint{new(big.Int).SetBytes(pbRp.T1.X),new(big.Int).SetBytes(pbRp.T1.Y)}
	mp.T2 = ECPoint{new(big.Int).SetBytes(pbRp.T2.X),new(big.Int).SetBytes(pbRp.T2.Y)}

	for i := 0;i < len(pbRp.BPG) ;i++  {
		newBH := ECPoint{new(big.Int).SetBytes(pbRp.BPH[i].X), new(big.Int).SetBytes(pbRp.BPH[i].Y)}
		newBG := ECPoint{new(big.Int).SetBytes(pbRp.BPG[i].X), new(big.Int).SetBytes(pbRp.BPG[i].Y)}
		mp.BPG = append(mp.BPG, newBG)
		mp.BPH = append(mp.BPH, newBH)
	}


	mp.Tau, ok = new(big.Int).SetString(pbRp.Tau, 10)
	mp.Th, ok = new(big.Int).SetString(pbRp.Th, 10)
	mp.Mu, ok = new(big.Int).SetString(pbRp.Mu, 10)
	if !ok {
		return errors.New("Unable to convert Strings to BigInt")

	}

	mp.IPP = InnerProdArg{}

	for i := 0;i < len(pbRp.IPP.L) ;i++  {
		newIPL :=  ECPoint{new(big.Int).SetBytes(pbRp.IPP.L[i].X),new(big.Int).SetBytes(pbRp.IPP.L[i].Y)}
		newIPR :=  ECPoint{new(big.Int).SetBytes(pbRp.IPP.R[i].X),new(big.Int).SetBytes(pbRp.IPP.R[i].Y)}
		mp.IPP.L = append(mp.IPP.L, newIPL)
		mp.IPP.R = append(mp.IPP.R, newIPR)
	}

	for i:= 0; i < len(pbRp.IPP.Challenges) ; i++  {
		tempChal, _ := new(big.Int).SetString(pbRp.IPP.Challenges[i], 10)
		mp.IPP.Challenges = append(mp.IPP.Challenges, tempChal)
	}

	mp.IPP.A, ok = new(big.Int).SetString(pbRp.IPP.A, 10)
	mp.IPP.B, ok = new(big.Int).SetString(pbRp.IPP.B, 10)
	mp.Cy, ok = new(big.Int).SetString(pbRp.Cy, 10)
	mp.Cz, ok = new(big.Int).SetString(pbRp.Cz, 10)
	mp.Cx, ok = new(big.Int).SetString(pbRp.Cx, 10)
	if !ok {
		return errors.New("Unable to convert Strings to BigInt")
	}
	return nil
}
