package ckks_cipher

import (
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

type RastaCTR struct {
    *RtBCipher
	iv         	[]byte
    blockSize	int
	keySize	    int
	rounds		int
	// bitIndex   	[]*BitSet
    bitSbox	   	[]*BitSet
    sboxMonomialOrder	[]*BitSet
	allZeroIn	bool
}

func NewRastaCTR(key_ []uint8, params_ ckks.Parameters, btpParams_ bootstrapping.Parameters, btpKey_ *bootstrapping.EvaluationKeys, encoder_ *ckks.Encoder, encryptor_ *rlwe.Encryptor, decryptor_ *rlwe.Decryptor, iv_ []byte) (*RastaCTR, error) {
    rtb, err := NewRtBCipher(key_, params_, btpParams_, btpKey_, encoder_, encryptor_, decryptor_)
    if err!= nil {
        return nil, err
    }
    rasta := &RastaCTR{
        RtBCipher: 	rtb,
        blockSize:	351,
		keySize: 	351,
		rounds:		6,
        iv:         iv_,
		allZeroIn: 	true, //debug mode
    }
	return rasta, err
}

func (rasta *RastaCTR) DebugTest(ciphertexts []byte, bits int) ([]*rlwe.Ciphertext, error) {
	if rasta.allZeroIn {
		bits = rasta.params.MaxSlots() * rasta.blockSize
	}
	numBlocks := int(math.Ceil(float64(bits) / float64(rasta.blockSize)))

	iv := NewBitSet(rasta.blockSize)
	iv.Set(0) // set iv all zero
	rasta.EncryptKey()
	rasta.EncryptInput(iv, numBlocks)
	state := rasta.inputEncrypted


	fmt.Println("aes.totalLevel", rasta.totalLevel)
	fmt.Println("aes.remain", rasta.remainingLevel)
	for i := 0; i < len(state); i++ {
		if state[i] == nil { 
			strMsg := "state[" + strconv.Itoa(i) + "] is nil, exit!"	
			panic(strMsg) 
		}

		rasta.DropLevel(state[i], rasta.totalLevel-rasta.remainingLevel)
	}
	rasta.DebugPrint(state[0], "Level")

	Start := time.Now()

	elasp := time.Since(Start)
	fmt.Println("\n\n\n\nOne round time: ", elasp)

	for i:=0;i<8;i++{
		rasta.DebugPrint(state[i], "0~after btp")
		
	}

	return state, nil
}

func (rasta *RastaCTR) HEDecrypt(ciphertexts []uint8, bits int) []*rlwe.Ciphertext {
	if rasta.allZeroIn {
		bits = rasta.params.MaxSlots() * rasta.blockSize
	}
	numBlock := int(math.Ceil(float64(bits) / float64(rasta.blockSize)))
	iv := NewBitSet(rasta.blockSize)
	iv.Set(0) // set iv all zero
	// rasta.EncryptKey()
	rasta.EncryptInput(iv, numBlock)

	for i := 0; i < len(rasta.inputEncrypted); i++ {
		if rasta.inputEncrypted[i].Level() > rasta.remainingLevel   {
			rasta.Evaluator.DropLevel(rasta.inputEncrypted[i], rasta.inputEncrypted[i].Level() - rasta.remainingLevel  )
		}
	}

	startAES := time.Now()
	// AES encryption **********************************************
	// state := rasta.AddWhiteKey( rasta.inputEncrypted, rasta.keyEncrypted )
	state := rasta.inputEncrypted
	for i := 1; i < 2; i++ {
		fmt.Printf("round iterator : %d\n", i)
		rasta.RoundFunction(state)
	}
	// AES encryption **********************************************
	for i:=0;i<8;i++{
		str := "Sbox: " + strconv.Itoa(i)
		rasta.DebugPrint(state[i], str)
	}

	endAES := time.Now()
	durationAES := endAES.Sub(startAES)
	fmt.Printf("代码执行时间：%d 秒 :: %d 毫秒\n", int(durationAES.Seconds()), int(durationAES.Milliseconds())%1000)
	// // Add cipher
	// // encode_ciphertext(ciphertexts, num_block);
	// for i := 0; i < len(state); i++ {
	// 	if (i%8 == 1) || (i%8 == 2) || (i%8 == 4) || (i%8 == 5) {
	// 		NOT( evals[0], state[i], state[i])
	// 	}
	// }

	// ch := make(chan int, len(state) )
	// for i := 0; i < len(state); i++ {
	// 	go func(i int) {
	// 		XOR(evals[i], state[i], aes.encodeCipher[i], state[i])
	// 		ch <- i
	// 	}(i)
	// }
	// for i := 0; i < len(state); i++ {
	// 	<-ch
	// }

	return state
}


func (rasta *RastaCTR) EncryptKey() {
    if rasta.encoder == nil || rasta.encryptor == nil {
        panic("encoder or encryptor is not initialized")
    }
    rasta.keyEncrypted = make([]*rlwe.Ciphertext, rasta.keySize)

    for i := 0; i < rasta.keySize; i++ {
        if i >= len(rasta.symmetricKey)*8 {
            panic("input symmetric key size is not match!")
        }
        bit := (rasta.symmetricKey[i/8] >> uint(i%8)) & 1
        keys := make([]float64, rasta.params.MaxSlots())
        for j := 0; j < rasta.params.MaxSlots(); j++ {
            keys[j] = float64(bit)
        }
        // fmt.Printf("Encoding bit %d which is %d\n", i, bit)
		pt := ckks.NewPlaintext( rasta.params, rasta.totalLevel)
        rasta.encoder.Encode(keys, pt)
        if pt == nil {
            panic("skPlain is nil after encoding")
        }
        // fmt.Println("Before encryption")
        rasta.keyEncrypted[i], _ = rasta.encryptor.EncryptNew(pt)		
    }
	if rasta.keyEncrypted[0] == nil {
		panic("skBitEncrypted is nil after encryption")
	}
    // fmt.Println("Encryption completed")
}

func (rasta *RastaCTR) EncryptInput(iv *BitSet, numBlock int) {
	rasta.inputEncrypted = make([]*rlwe.Ciphertext, rasta.blockSize)
	inputData := make([]*BitSet, rasta.params.MaxSlots() )
	for i, block := range inputData{
		block = NewBitSet(rasta.blockSize)
		inputData[i] = block
	}

	for i := range inputData {
		if rasta.allZeroIn {
			inputData[i].Set(0xffffffffffffff)
		} else {
			inputData[i].Set( int(ctr(iv, uint64(i+1) ).ToULong()) )
		}
	}
	for i := 0; i < rasta.blockSize; i++ {
		stateBatched := make([]float64, rasta.params.MaxSlots())
		for j := 0; j < rasta.params.MaxSlots(); j++ {
			stateBatched[j] = float64(inputData[j].bits[i])
		}
		pt := ckks.NewPlaintext( rasta.params, rasta.totalLevel)
		rasta.encoder.Encode( stateBatched, pt)
		rasta.inputEncrypted[i], _ = rasta.encryptor.EncryptNew(pt)
	}
	if rasta.inputEncrypted[0] == nil {panic("input is not stored in aesStruct")}
}

func (rasta *RastaCTR) EncodeCiphertext(ciphertexts []uint8, numBlock int) {
	rasta.encodeCipher = make([]*rlwe.Ciphertext, rasta.blockSize)
	if numBlock < rasta.params.MaxSlots() {
		fmt.Println("data is not full pack, fill with 0...")
	}
	encryptedData := make([]*BitSet, numBlock)
	for i, bit := range encryptedData {
		bit = NewBitSet(rasta.blockSize)
		encryptedData[i] = bit 
	}

	for i := range encryptedData {
		if i < numBlock {
			if rasta.allZeroIn {
				encryptedData[i].Set(0)
			} else {
				for k := 0; k < rasta.blockSize && i*rasta.blockSize+k < numBlock*rasta.blockSize; k++ {
					ind := i*rasta.blockSize + k
					bit := (ciphertexts[ind/8] >> uint(ind%8)) & 1
					encryptedData[i].bits[k] = uint8(bit)
				}
			}
		} else {
			encryptedData[i].Set(0)
		}
	}
	for i := 0; i < rasta.blockSize; i++ {
		var data []float64
		for j := 0; j < rasta.params.MaxSlots(); j++ {
			data = append(data, float64( encryptedData[j].bits[i] ) )
		}
		pt := ckks.NewPlaintext( rasta.params, rasta.remainingLevel)
		rasta.encoder.Encode(data, pt)
		rasta.encodeCipher[i], _ = rasta.encryptor.EncryptNew(pt)
	}
	if rasta.encodeCipher[0] == nil {panic("encodeCiphertext is nil")}
}

func (cipher *RastaCTR) RoundFunction( state []*rlwe.Ciphertext ) {
	// SubByte
	fmt.Printf("Chain index before sbox: %d, scale: %f\n", state[77].Level(), state[77].LogScale() )
	stateCopy := make( []*rlwe.Ciphertext, len(state) )
	ch := make(chan bool, 351)
	for i := 0; i < 351; i++ {
		go func(i int) {
			evalCopy := cipher.Evaluator.ShallowCopy()
			stateCopy[i], _ = evalCopy.MulRelinNew(state[(i+1)%351], state[(i+2)%351])
			evalCopy.Rescale(stateCopy[i], stateCopy[i])
			stateCopy[i], _ = evalCopy.AddNew(stateCopy[i], state[(i+2)%351])
			ch <- true
		}(i)
	}
	for i := 0; i < 351; i++ {
		<-ch
	}

	for i:=0;i<351;i++{
		state[i], _ = cipher.Evaluator.AddNew(stateCopy[i], state[i])
	}
	stateCopy = nil

	// MixColumn
	cipher.FreeMixColumn( state )
	cipher.DebugPrint(state[0], "After mixcolumn")
	fmt.Printf("MixColumn Chain: %d, scale: %f\n", state[0].Level(), state[0].LogScale() )
	// Parallel processing for bootstrapping and cleaning tensor
	ch = make(chan bool, 175)
	for i:=0; i<175; i++ {
		go func(i int) {
			evalCopy := cipher.Evaluator.ShallowCopy()
			state[i], state[175 + i], _ = evalCopy.BootstrapCmplxThenDivide(state[i], state[175 + i])
			if i == 0 {
				cipher.DebugPrint(state[i], "BTS precise: ")
			}
			ch <- true
		}(i)
	}
	for i := 0; i < 175; i++ {
		<-ch
	}
}

func (cipher *RastaCTR) AddWhiteKey( pt, key []*rlwe.Ciphertext)  []*rlwe.Ciphertext {
	ch := make(chan bool, len(pt))
	for i := 0; i < len(pt); i++ {
		go func(i int) {
			evalCopy := cipher.Evaluator.ShallowCopy()
			pt[i] = XORNew(evalCopy, pt[i], key[i])
			evalCopy.ScaleUp(pt[i], rlwe.NewScale(2), pt[i])
			ch <- true
		}(i)
	}
	for i := 0; i < len(pt); i++ {
		<-ch
	}	
	return pt
}


// Free XOR components**************************************
func (cipher *RastaCTR) FreeAddRoundKey( state, key []*rlwe.Ciphertext) {
	for i := 0; i < len(state); i++ {
		FXOR(cipher.Evaluator, state[i], key[i], state[i])
	}
}

func (cipher *RastaCTR) FreeMixColumn( x []*rlwe.Ciphertext ) {
	plainVec := make([]float64, cipher.params.MaxSlots())
	for i := 0; i < len(plainVec); i++ {
		plainVec[i] = 1
	} 
	stateCopy := make([]*rlwe.Ciphertext, len(x))
	for i := 0; i < 351; i++ {
		stateCopy[i] = x[i].CopyNew()
	}
	ch := make(chan bool, 351)
	for i := 0; i < 351; i++ {
		go func(i int) {
			evalCopy := cipher.Evaluator.ShallowCopy()
			for j := 0; j < 351; j++ {
				evalCopy.MulThenAdd(x[j], plainVec, stateCopy[i])
			} 
			evalCopy.Rescale(stateCopy[i], stateCopy[i])
			ch <- true
		}(i)
	}
	for i := 0; i < 351; i++ {
		<-ch
	}	
	copy(x, stateCopy)
}