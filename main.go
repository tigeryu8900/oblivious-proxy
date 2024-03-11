package main

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/schemes/bfv"
	"ixxoprivacy/pkg/compiler"
	"ixxoprivacy/pkg/interpreter"
)

func pow(eval *bfv.Evaluator, op0 *rlwe.Ciphertext, op1 uint64) (opOut *rlwe.Ciphertext) {
	if op1 == 1 {
		return op0
	} else {
		result := pow(eval, op0, op1/2)
		eval.MulRelin(result, result, result)
		if op1%2 == 1 {
			eval.Mul(result, op0, result)
		}
		return result
	}
}

func compare(eval *bfv.Evaluator, negonespt *rlwe.Plaintext, op0 *rlwe.Ciphertext, op1 *rlwe.Plaintext) (opOut *rlwe.Ciphertext) {
	onehotct, _ := eval.SubNew(op0, op1)
	onehotct = pow(eval, onehotct, eval.GetParameters().PlaintextModulus()-1)
	eval.Mul(onehotct, negonespt, onehotct)
	eval.Sub(onehotct, negonespt, onehotct)
	return onehotct
}

func main() {
	// Users
	fmt.Println("Compiling circuit...")
	cir, _ := compiler.CircuitFromJS("shuffle-requests.js")

	fmt.Println("Getting inputs...")
	inputs := interpreter.GetAllInputs(cir.Inputs, []string{"server.json", "user1.json", "user2.json", "user3.json"})

	// Server
	fmt.Println("Interpreting...")
	out := interpreter.Interprete(cir, inputs)

	interpreter.SaveOutput(out[0], cir.Outputs[0].Type, "shuffled.json")

	shuffled := interpreter.GetGoValue(out[0], cir.Outputs[0].Type)

	// Server and Users
	params, _ := bfv.NewParametersFromLiteral(bfv.ParametersLiteral{
		LogN: 14,
		Q: []uint64{
			0x100000000060001,
			0x80000000068001,
			0x80000000080001,
			0x3fffffffef8001,
			0x40000000120001,
			0x3fffffffeb8001,
		}, // 56 + 55 + 55 + 54 + 54 + 54 bits
		P: []uint64{
			0x80000000130001,
			0x7fffffffe90001,
		}, // 55 + 55 bits
		PlaintextModulus: 17,
	})
	encoder := bfv.NewEncoder(params)
	keygen := bfv.NewKeyGenerator(params)

	// Server
	keys := []int64{0, 0, 0}
	responses := []int64{0, 0, 0}
	for i, entry := range shuffled.([]interface{}) {
		keys[i] = entry.(map[string]interface{})["key"].(int64)
		responses[i] = 2*entry.(map[string]interface{})["request"].(int64) + 1
	}
	keyspt := bfv.NewPlaintext(params)
	responsespt := bfv.NewPlaintext(params)
	negonespt := bfv.NewPlaintext(params)
	encoder.Encode(keys, keyspt)
	encoder.Encode(responses, responsespt)
	encoder.Encode([]int64{-1, -1, -1}, negonespt)

	// User 1
	sk1, pk1 := keygen.GenKeyPairNew()
	enc1 := bfv.NewEncryptor(params, pk1)
	dec1 := bfv.NewDecryptor(params, sk1)
	keypt1 := bfv.NewPlaintext(params)
	encoder.Encode([]int64{12, 12, 12}, keypt1)
	keyct1, _ := enc1.EncryptNew(keypt1)
	eval1 := bfv.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(keygen.GenRelinearizationKeyNew(sk1)))

	// User 2
	sk2, pk2 := keygen.GenKeyPairNew()
	enc2 := bfv.NewEncryptor(params, pk2)
	dec2 := bfv.NewDecryptor(params, sk2)
	keypt2 := bfv.NewPlaintext(params)
	encoder.Encode([]int64{34, 34, 34}, keypt2)
	keyct2, _ := enc2.EncryptNew(keypt2)
	eval2 := bfv.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(keygen.GenRelinearizationKeyNew(sk2)))

	// User 3
	sk3, pk3 := keygen.GenKeyPairNew()
	enc3 := bfv.NewEncryptor(params, pk3)
	dec3 := bfv.NewDecryptor(params, sk3)
	keypt3 := bfv.NewPlaintext(params)
	encoder.Encode([]int64{56, 56, 56}, keypt3)
	keyct3, _ := enc3.EncryptNew(keypt3)
	eval3 := bfv.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(keygen.GenRelinearizationKeyNew(sk3)))

	// Server
	onehotct1 := compare(eval1, negonespt, keyct1, keyspt)
	resultct1, _ := eval1.MulRelinNew(onehotct1, responsespt)
	onehotct2 := compare(eval2, negonespt, keyct2, keyspt)
	resultct2, _ := eval2.MulRelinNew(onehotct2, responsespt)
	onehotct3 := compare(eval3, negonespt, keyct3, keyspt)
	resultct3, _ := eval3.MulRelinNew(onehotct3, responsespt)

	// User 1
	resultpt1 := dec1.DecryptNew(resultct1)
	result1 := []int64{0, 0, 0}
	encoder.Decode(resultpt1, result1)
	res1 := result1[0] + result1[1] + result1[2]
	fmt.Println("User 1 got a response", res1)

	// User 2
	resultpt2 := dec2.DecryptNew(resultct2)
	result2 := []int64{0, 0, 0}
	encoder.Decode(resultpt2, result2)
	res2 := result2[0] + result2[1] + result2[2]
	fmt.Println("User 2 got a response", res2)

	// User 3
	resultpt3 := dec3.DecryptNew(resultct3)
	result3 := []int64{0, 0, 0}
	encoder.Decode(resultpt3, result3)
	res3 := result3[0] + result3[1] + result3[2]
	fmt.Println("User 3 got a response", res3)
}
