package main

import (
	"runtime"

	"github.com/tuneinsight/lattigo/v6/chisqtest"
)

func main() {
	runtime.GOMAXPROCS(64)
	// ./chi2 --SNPdir "../data" --SNPfilename "random_sample" --pvalue "pvalue.txt" --runtime "result.txt" --samplesize="200" --snps="16384"
	
	SNPDir := "../../chisqtest/data"
	SNPFileName := "random_sample"
	pValue := "pvalue.txt"
	Runtime := "result.txt"
	SampleSize := "64" // 64 individual data per transcipering 
	SNPs := "16384"
	chisqtest.RunChi2(SNPDir, SNPFileName, pValue, Runtime, SampleSize, SNPs);
}