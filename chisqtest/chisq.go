package chisqtest

import (
	"encoding/csv"
	"fmt"
	"log"
	"math"
	"os"
	"strconv"
	"time"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/dft"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/mod1"
	"github.com/tuneinsight/lattigo/v6/ckks_cipher"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)


const EPSILON float64 = 1.0E-08


func ReadSNPFile(headers *[]string, dataColumns *[][]float64, y *[]float64, dataFileName string, N, M int) error {
	fileName := dataFileName + ".csv"
	fmt.Fprintf(os.Stderr, "file name = %s\n", fileName)

	file, err := os.Open(fileName)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.TrimLeadingSpace = true

	// Read the header line
	line, err := reader.Read()
	if err != nil {
		return fmt.Errorf("failed to read header line: %w", err)
	}

	cols := len(line)
	for i, value := range line {
		if value != "" && i > 4 && i < M+5 {
			*headers = append(*headers, value)
		}
	}

	count := 0
	for {
		if count >= N {
			break
		}
		line, err := reader.Read()
		if err != nil {
			break
		}

		if len(line) > 2 {
			yval, err := strconv.ParseFloat(line[1], 64)
			if err != nil {
				return fmt.Errorf("failed to parse float from line[1]: %w", err)
			}
			*y = append(*y, yval)

			var row []float64
			for i := 5; i < cols; i++ {
				val, err := strconv.ParseFloat(line[i], 64)
				if err != nil {
					return fmt.Errorf("failed to parse float from line[%d]: %w", i, err)
				}
				row = append(row, val)
			}
			*dataColumns = append(*dataColumns, row)
		}
		count++
	}

	fmt.Printf("Read in data: %s\n", dataFileName)
	return nil
}

// BS 
func BS(z float64) float64 {
	y := math.Exp(-z * z / 2)
	return math.Sqrt(1-y) * (31*y/200 - 341*y*y/8000) / math.Sqrt(math.Pi)
}

// normalCFD 
func normalCFD(value float64) float64 {
	return 0.5 * math.Erfc( math.Sqrt2/(-value) )
}

// sf 
func sf(value float64) float64 {
	return 1 - normalCFD(value)
}

func Equal(a, b float64) bool {
	return EPSILON > math.Abs(a-b)
}

func Less(a, b float64) bool {
	return (a - b) < (-EPSILON)
}

func Greater(a, b float64) bool {
	return (a - b) > EPSILON
}

// IncompleteGamma 
func IncompleteGamma(val, p float64) float64 {
	if !Greater(val, 0) || !Greater(p, 0) {
		return 0
	}
	LgammaP, _ := math.Lgamma(p)
	expValue := p*math.Log(val) - val - LgammaP
	if Less(expValue, math.Log(1.0E-37)) { // underflow
		return 0
	}
	factor := math.Exp(expValue)
	if !Greater(val, 1) || Less(val, p) {
		igamma := 1.0
		term := 1.0
		for i := 1; Greater(term, EPSILON); i++ {
			term *= (val / (p + float64(i)))
			igamma += term
		}
		return (igamma * factor / p)
	}

	pn := [6]float64{1, val, val + 1, val * (2 + val - p)}
	upperIncGamma := pn[2] / pn[3]
	for j := 1; ; j++ {
		a := (float64(j)+1)*2 + val - p
		b := (1 + float64(j) - p) * float64(j)
		pn[4] = a*pn[2] - b*pn[0]
		pn[5] = a*pn[3] - b*pn[1]
		if !Equal(pn[5], 0) {
			rn := pn[4] / pn[5]
			diff := math.Abs(upperIncGamma - rn)
			if !Greater(diff, EPSILON) && !Greater(diff, (EPSILON*rn)) {
				return (1 - factor*upperIncGamma)
			}
			upperIncGamma = rn
		}
		for i := 0; i < 4; i++ {
			pn[i] = pn[i+2]
		}
		if !Greater(1.0E+37, math.Abs(pn[4])) { // overflow
			for i := 0; i < 4; i++ {
				pn[i] = pn[i] / 1.0E+37
			}
		}
	}

}


func BinaryTreeAdd(vector []*rlwe.Ciphertext, evaluator *bootstrapping.Evaluator) *rlwe.Ciphertext {

	for j := 1; j < len(vector); j=j*2 {
		for i := 0; i<len(vector); i = i + 2*j {
			if (i+j)<len(vector) {
				evaluator.Add(vector[i], vector[i+j], vector[i])
			}				
		}
	}
	return vector[0]
}


func FormatInputData(formattedData [][]float64, blockNum int) []uint8 {
    var formatedInputData []uint8 // blockNum is MaxSlots
    numSNP := blockNum //Set to MaxSlots = blockNum in default

    if len(formattedData) < 64 {
        panic("formattedData must have at least 64 rows")
    }

    for _, row := range formattedData {
        if len(row) < numSNP {
            panic("Each row in formattedData must have at least numSNP elements") // fixed input format
        }
    }

    for j := 0; j < numSNP; j++{
		for k := 0; k < 16; k++{
			var tmp uint8
			for ind := 3; ind > -1; ind--{
				snp := uint8(math.Round(formattedData[ 4*k + ind ][j]))
				if snp > 2{
					panic("Input SNP feature out of range!\n")
				}
                bits := snp
                tmp = (tmp << 2) | bits
			}
			formatedInputData = append(formatedInputData, tmp)
		}
	}

	return formatedInputData
}


func RunChi2(SNPDir, SNPFileName, pValue, Runtime, SampleSize, SNPs string) {
	N, err := strconv.Atoi(SampleSize)
	if err != nil {
		log.Fatalf("SampleSize transform error: %v", err)
	}
	M, err := strconv.Atoi(SNPs)
	if err != nil {
		log.Fatalf("SNPs transform error: %v", err)
	}
	scalingFactor := 0.1*math.Pow(float64(N), -2)

	var headersS []string
	var sData [][]float64
	var yData []float64


	err = ReadSNPFile(&headersS, &sData, &yData, SNPDir+"/"+SNPFileName, N, M)
	if err != nil {
		log.Fatalf("ReadSNPFile error: %v", err)
	}
	for i:=0;i<10;i++{
		fmt.Println(headersS[i])
	}

	fmt.Println("Number of Individuals =", len(sData))
	fmt.Println("Number of SNPs =", len(sData[0]))
	fmt.Println("Number of yData =", len(yData))

	// AES transcipher process
	LogN := 15
	LogDefaultScale := 35

	q0 := []int{36}                                    // 3) ScaleDown & 4) ModUp
	qiSlotsToCoeffs := []int{35, 35}               // 1) SlotsToCoeffs
	// qiCircuitSlots := []int{35, 35, 35}           // 0) Circuit in the slot domain
	qiCircuitSlots := []int{ 35, 35, 35 }           // 0) Circuit in the slot domain
	qiEvalMod := []int{36, 36, 36, 36, 36, 36, 36} // 6) EvalMod
	qiCoeffsToSlots := []int{34, 34, 34, 34}           // 5) CoeffsToSlots
	
	workingLevel := len(qiSlotsToCoeffs) + len(qiCircuitSlots) // Specify the working level to reduce Mul complexity
	
	LogQ := append(q0, qiSlotsToCoeffs...)
	LogQ = append(LogQ, qiCircuitSlots...)
	LogQ = append(LogQ, qiEvalMod...)
	LogQ = append(LogQ, qiCoeffsToSlots...)

	params, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            LogN,                                              // Log2 of the ring degree
		LogQ:            LogQ, // Log2 of the ciphertext prime moduli
		LogP:            []int{36, 36, 36, 36, 36},                                 // Log2 of the key-switch auxiliary prime moduli
		LogDefaultScale: LogDefaultScale,                                                // Log2 of the scale
		Xs:              ring.Ternary{H: 256},
	})
	if err != nil {
		panic(err)
	}

	// CoeffsToSlots parameters (homomorphic encoding)
	CoeffsToSlotsParameters := dft.MatrixLiteral{
		Type:         dft.HomomorphicEncode,
		Format:       dft.RepackImagAsReal, // Returns the real and imaginary part into separate ciphertexts
		LogSlots:     params.LogMaxSlots(),
		LevelQ:       params.MaxLevelQ(),
		LevelP:       params.MaxLevelP(),
		LogBSGSRatio: 1,
		Levels:       []int{1, 1, 1, 1}, //qiCoeffsToSlots
	}

	// Parameters of the homomorphic modular reduction x mod 1
	Mod1ParametersLiteral := mod1.ParametersLiteral{
		LevelQ:          params.MaxLevel() - CoeffsToSlotsParameters.Depth(true),
		LogScale:        36,               // Matches qiEvalMod
		Mod1Type:        mod1.CosDiscrete, // Multi-interval Chebyshev interpolation
		Mod1Degree:      120,               // Depth 5
		DoubleAngle:     0,                // Depth 3
		K:               14,               // With EphemeralSecretWeight = 32 and 2^{15} slots, ensures < 2^{-138.7} failure probability
		LogMessageRatio: 1,               // q/|m| = 2^10
		Mod1InvDegree:   0,                // Depth 0
	}

	// SlotsToCoeffs parameters (homomorphic decoding)
	SlotsToCoeffsParameters := dft.MatrixLiteral{
		Type:         dft.HomomorphicDecode,
		LogSlots:     params.LogMaxSlots(),
		LogBSGSRatio: 1,
		LevelP:       params.MaxLevelP(),
		Levels:       []int{1, 1}, // qiSlotsToCoeffs
	}

	SlotsToCoeffsParameters.LevelQ = len(SlotsToCoeffsParameters.Levels)

	// Custom bootstrapping.Parameters.
	// All fields are public and can be manually instantiated.
	btpParams := bootstrapping.Parameters{
		ResidualParameters:      params,
		BootstrappingParameters: params,
		SlotsToCoeffsParameters: SlotsToCoeffsParameters,
		Mod1ParametersLiteral:   Mod1ParametersLiteral,
		CoeffsToSlotsParameters: CoeffsToSlotsParameters,
		EphemeralSecretWeight:   32, // > 128bit secure for LogN=16 and LogQP = 115.
		CircuitOrder:            bootstrapping.DecodeThenModUp,
	}


	// We print some information about the residual parameters.
	fmt.Printf("Residual parameters: logN=%d, logSlots=%d, H=%d, sigma=%f, logQP=%f, levels=%d, scale=2^%d\n",
		btpParams.ResidualParameters.LogN(),
		btpParams.ResidualParameters.LogMaxSlots(),
		btpParams.ResidualParameters.XsHammingWeight(),
		btpParams.ResidualParameters.Xe(), params.LogQP(),
		btpParams.ResidualParameters.MaxLevel(),
		btpParams.ResidualParameters.LogDefaultScale())

	// And some information about the bootstrapping parameters.
	// We can notably check that the LogQP of the bootstrapping parameters is smaller than 1550, which ensures
	// 128-bit of security as explained above.
	fmt.Printf("Bootstrapping parameters: logN=%d, logSlots=%d, H(%d; %d), sigma=%f, logQP=%f, levels=%d, scale=2^%d\n",
		btpParams.BootstrappingParameters.LogN(),
		btpParams.BootstrappingParameters.LogMaxSlots(),
		btpParams.BootstrappingParameters.XsHammingWeight(),
		btpParams.EphemeralSecretWeight,
		btpParams.BootstrappingParameters.Xe(),
		btpParams.BootstrappingParameters.LogQP(),
		btpParams.BootstrappingParameters.QCount(),
		btpParams.BootstrappingParameters.LogDefaultScale())

	// Scheme context and keys

	//===========================
	//=== 4) KEYGEN & ENCRYPT ===
	//===========================

	// Now that both the residual and bootstrapping parameters are instantiated, we can
	// instantiate the usual necessary object to encode, encrypt and decrypt.

	// Scheme context and keys
	kgen := rlwe.NewKeyGenerator(params)

	sk, pk := kgen.GenKeyPairNew()

	encoder := ckks.NewEncoder(params)
	decryptor := rlwe.NewDecryptor(params, sk)
	encryptor := rlwe.NewEncryptor(params, pk)

	fmt.Println()
	fmt.Println("Generating bootstrapping evaluation keys...")
	evk, _, err := btpParams.GenEvaluationKeys(sk)
	if err != nil {
		panic(err)
	}
	fmt.Println("Done")

	//========================
	//=== 5) BOOTSTRAPPING ===
	//========================
	iv := make([]uint8, 16)
	symmetricKey := []byte{ // All zero symmetric key for debugging
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    }
	// symmetricKey := []byte{
    //     0xff, 0xff, 0xff, 0xff,
    //     0xff, 0xff, 0xff, 0xff,
    //     0xff, 0xff, 0xff, 0xff,
    //     0xff, 0xff, 0xff, 0xff,
    // }
	aes, _ := ckks_cipher.NewAESCtr(symmetricKey, params, btpParams, evk, encoder, encryptor, decryptor, iv) 
	// Encode the ciphertext into plain polynomimal
	// aes.HEDecrypt(symmetricKey, 128 )
	fmt.Println("aes.Parameters.LogMaxSlots(): ", params.MaxSlots())
	formatedData := FormatInputData(sData, params.MaxSlots())	
	aes.EncodeCiphertext(formatedData, params.MaxSlots())

	// Transciphering process is finished, thereby subsequent chisqtest is as follows
	eval := aes.ShallowCopy()

	startTime := time.Now()

	sCiphertexts := make([]*rlwe.Ciphertext, N) // N is the sample Size, i.e., the individual number
	if len(sCiphertexts) != len(aes.EncodedCT)/2 {
		fmt.Println("sCiphertext length: ", len(sCiphertexts), ", EncodedCT length: ", len(aes.EncodedCT))
		panic("Required SNP ciphertext length not match Transciphred data!")
	}
	for i := 0; i < N; i++{
		sCiphertexts[i], _ = eval.AddNew(aes.EncodedCT[2*i], aes.EncodedCT[2*i+1])
		eval.Add(aes.EncodedCT[2*i+1], sCiphertexts[i], sCiphertexts[i])
	}

	for i := 0; i < N/2; i++{
		str := "CT[" + strconv.Itoa(i) + "]: "
		printDebug(str, params, sCiphertexts[i], decryptor, encoder)
	}
	
	// for i := 0; i < N; i++ {
	// 	S := ckks.NewCiphertext(params, 1, workingLevel)
	// 	plaintext := ckks.NewPlaintext(params, workingLevel)
	// 	encoder.Encode( sData[i], plaintext )
	// 	encryptor.Encrypt(plaintext, S)
	// 	for S.Level() > workingLevel {
	// 		eval.DropLevel(S, 1)
	// 	}
	// 	sCiphertexts[i] = S
	// }

	yCiphertexts := make([]*rlwe.Ciphertext, N)
	for i := 0; i < N; i++ {
		individual := make([]float64, M)
		for j:=0;j<M;j++{
			individual[j] = yData[i]
		}
		plaintext := ckks.NewPlaintext(params, workingLevel)
		encoder.Encode( individual, plaintext )
		yCiphertexts[i], err = encryptor.EncryptNew(plaintext)
		if err != nil {
			panic(err)
		}
		for yCiphertexts[i].Level() > workingLevel {
			eval.DropLevel(yCiphertexts[i], 1)
		}
	}

	dVal := make([]float64, M)
	for i, _ := range dVal {
		tmp := float64(N)
		dVal[i] = 2 * tmp
	}
	// d := encoder.EncodeComplexNTTNew( dVal, params.LogSlots())

	dValScaled := make([]float64, M)
	for i, _ := range dValScaled {
		tmp := float64(N)
		dValScaled[i] = 2 * tmp * scalingFactor
	}
	dScaled := ckks.NewPlaintext(params, workingLevel)
	encoder.Encode(dValScaled, dScaled)

	start := time.Now()

	ySum := make([]*rlwe.Ciphertext, len(yCiphertexts) )
	for i := range yCiphertexts {
		ySum[i] = yCiphertexts[i].CopyNew()
	}
	yU := BinaryTreeAdd(ySum, eval)

	var chiD, chiN, orD, orN *rlwe.Ciphertext 
	ySMult := make([]*rlwe.Ciphertext, N)

	for i := 0; i < N; i++ {
		ySMult[i], _ = eval.MulRelinNew(sCiphertexts[i], yCiphertexts[i])
		eval.Rescale(ySMult[i], ySMult[i])
	}

	n11 := BinaryTreeAdd(ySMult, eval)
	c1 := BinaryTreeAdd(sCiphertexts, eval)
	
	printDebug( "n11: ", params, n11, decryptor, encoder)
	printDebug( "c1: ", params, c1, decryptor, encoder)
	printDebug( "yU: ", params, yU, decryptor, encoder)

	// r1 = 2 * yU
	r1, _ := eval.AddNew(yU, yU)
	r1Scaled, err := eval.MulNew(r1, float64(scalingFactor) )
	if err != nil {
		panic(err)
	}
	eval.Rescale(r1Scaled, r1Scaled)

	c1Scaled, err := eval.MulNew(c1, float64(scalingFactor) )
	eval.Rescale(c1Scaled, c1Scaled)
	if err != nil {
		panic(err)
	}
	// compute Chi2
	mult1, err := eval.MulRelinNew(n11, dScaled)
	eval.Rescale(mult1, mult1)
	if err != nil {
		panic(err)
	}
	mult2, err := eval.MulRelinNew(c1, r1Scaled)
	eval.Rescale(mult2, mult2)
	if err != nil {
		panic(err)
	}
	chiN1, err := eval.SubNew(mult1, mult2)
	if err != nil {
		panic(err)
	}
	chiN, err = eval.MulRelinNew(chiN1, chiN1)
	if err != nil {
		panic(err)
	}
	// denominator
	negC1Scaled, _ := eval.MulNew(c1Scaled, -1)
	chiD1, err := eval.AddNew(negC1Scaled, dScaled)
	if err != nil {
		panic(err)
	}
	chiD1, err = eval.MulRelinNew(chiD1, c1)
	if err != nil {
		panic(err)
	}
	eval.Rescale(chiD1, chiD1)
	negR1Scaled, _ := eval.MulNew(r1Scaled, -1)
	chiD2, _ := eval.AddNew(negR1Scaled, dScaled)
	chiD2, err = eval.MulRelinNew(chiD2, r1)
	eval.Rescale(chiD2, chiD2)
	if err != nil {
		panic(err)
	}
	chiD, err = eval.MulRelinNew( chiD1, chiD2 )
	eval.Rescale(chiD, chiD)
	if err != nil {
		panic(err)
	}
	// Odds Ratio
	n11Scaled, _ := eval.MulNew(n11, float64(scalingFactor) )
	eval.Rescale(n11Scaled, n11Scaled)
	
	// denominator
	or2, _ := eval.SubNew(c1, n11)
	or3, _ := eval.SubNew(r1Scaled, n11Scaled)

	orD, err = eval.MulRelinNew(or2, or3)
	eval.Rescale(orD, orD)
	if err != nil {
		panic(err)
	}

	// numerator
	or1, _ := eval.SubNew(n11Scaled, r1Scaled)
	or1, _ = eval.SubNew(or1, c1Scaled)
	or1, _ = eval.AddNew(or1, dScaled)
	
	orN, _ = eval.MulRelinNew(n11, or1)
	eval.Rescale(orN, orN)
	endToEndTime := float64(time.Since(start).Seconds())


	pN := decryptor.DecryptNew(chiN)
	pD := decryptor.DecryptNew(chiD)
	oddN := decryptor.DecryptNew(orN)
	oddD := decryptor.DecryptNew(orD)
	
	msg_pN := make([]float64, len(headersS))
	msg_pD := make([]float64, len(headersS))
	msg_oddN := make([]float64, len(headersS))
	msg_oddD := make([]float64, len(headersS))

	encoder.Decode(pN, msg_pN)
	encoder.Decode(pD, msg_pD)
	encoder.Decode(oddN, msg_oddN)
	encoder.Decode(oddD, msg_oddD)

	chival := make([]float64, len(headersS))
	pval := make([]float64, len(headersS))
	odds := make([]float64, len(headersS))

	for i := 0; i < len(headersS); i++ {
		chival[i] = msg_pN[i] * 2 * float64(N) / msg_pD[i]
		if chival[i] < 0 {
			chival[i] = 0
		}
		pval[i] = 1 - IncompleteGamma(chival[i]/2, 0.5)
		if pval[i] < 0 {
			pval[i] = 1e-15
		} else {
			if pval[i] == 0 {
				pval[i] = BS(math.Sqrt(chival[i]))
			}
		}
		odds[i] = msg_oddN[i] / msg_oddD[i]
	}	

	writeResults("pValue.txt", headersS, pval)
	writeResults("odds.txt", headersS, odds)
	writeResults("chi2.txt", headersS, chival)

	// keyGenTime := float64(time.Since(startKeyGen).Seconds())
	// encryptionTime := float64(time.Since(startEnc).Seconds())
	// computationTime := float64(time.Since(startComp).Seconds())
	// decryptionTime := float64(time.Since(startDec).Seconds())
	
	// fmt.Printf("\nKey Generation Time: \t\t%.3f s\n", keyGenTime)
	// fmt.Printf("Encoding and Encryption Time: \t%.3f s\n", encryptionTime)
	// fmt.Printf("Computation Time: \t\t%.3f s\n", computationTime)
	// fmt.Printf("Decryption & Decoding Time: \t%.3f s\n", decryptionTime)
	fmt.Printf("\nEnd-to-end Runtime: \t\t%.3f s\n", endToEndTime)

	// writeRuntime("runtime.txt", keyGenTime, encryptionTime, computationTime, decryptionTime, endToEndTime)

	duration := time.Since(startTime)
	fmt.Printf("End-to-end Runtime: %.2f s\n", duration.Seconds())
}

func writeResults(filename string, headersS []string, values []float64) {
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	for i := 0; i < len(headersS); i++ {
		fmt.Fprintf(file, "%s\t%f\n", headersS[i], values[i])
	}
}

func writeRuntime(filename string, keyGenTime, encryptionTime, computationTime, decryptionTime, endToEndTime float64) {
    file, err := os.Create(filename)
    if err != nil {
        panic(err)
    }
    defer file.Close()

    fmt.Fprintf(file, "Key Generation Time: \t\t%.3f s\n", keyGenTime)
    fmt.Fprintf(file, "Encoding and Encryption Time: \t%.3f s\n", encryptionTime)
    fmt.Fprintf(file, "Computation Time: \t\t%.3f s\n", computationTime)
    fmt.Fprintf(file, "Decryption & Decoding Time: \t%.3f s\n", decryptionTime)
    fmt.Fprintf(file, "End-to-end Runtime: \t\t%.3f s\n", endToEndTime)
}

func printDebug( str string, params ckks.Parameters, ciphertext *rlwe.Ciphertext, decryptor *rlwe.Decryptor, encoder *ckks.Encoder) {

	fmt.Println(str)
	valuesTest := make([]float64, params.MaxSlots())
	encoder.Decode(decryptor.DecryptNew(ciphertext), valuesTest)

	fmt.Printf("Level: %d (logQ = %d)\n", ciphertext.Level(), params.LogQLvl(ciphertext.Level()))
	fmt.Printf("Scale: 2^%f\n", ciphertext.LogScale())
	fmt.Printf("ValuesTest: %6.10f %6.10f %6.10f %6.10f...\n", valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3])
}
