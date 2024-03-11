# oblivious-proxy

This is a proof-of-concept of an oblivious proxy.

## Threat Model

This implementation considers the scenario where an adversary compromises the server and is acting as some of the users.

The adversary should not be able to associate the requests with the remaining users.

## The Circuit

We have a circuit defined in `shuffle-requests.js` that shuffles the requests before returning them to the server.

Party `0` is the server (evaluator), and parties `1`, `2`, and `3` are the users (scrambler).

Each user inputs a `key`, which would be used with PIR-by-keyword to retrieve the response, a `request`, and a `seed`,
which would be xored together and used as the seed of a random function.

`user1.json`, `user2.json`, and `user3.json` represents the inputs for the users, and `server.json` represents the input
for the server, which would be a dummy value.

## Implementation

`main.go` contains the implementation of the proxy.

### Setting Up the Garbled Circuit

The first step is to compile the garbled circuit and gathering the inputs.

```go
// Users
fmt.Println("Compiling circuit...")
cir, _ := compiler.CircuitFromJS("shuffle-requests.js")

fmt.Println("Getting inputs...")
inputs := interpreter.GetAllInputs(cir.Inputs, []string{"server.json", "user1.json", "user2.json", "user3.json"})
```

The garbled circuit guarantees that neither the server nor the other users can tell what a user's request is.

### Interpreting the Circuit

Then, the server interprets the circuit and gets the shuffled results. The server has no way of knowing which request
belongs to which user.

```go
// Server
fmt.Println("Interpreting...")
out := interpreter.Interprete(cir, inputs)

interpreter.SaveOutput(out[0], cir.Outputs[0].Type, "shuffled.json")

shuffled := interpreter.GetGoValue(out[0], cir.Outputs[0].Type)
```

The server does not know which request corresponds to which user since the requests are shuffled.

### Setting Up BFV

The next step is to set up BFV. The server and users will share the same parameters.

```go
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
```

### Setting up PIR-by-Keyword

Then, the server sets up PIR-by-keyword. This example uses `2 * request + 1` as the response.

```go
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
```

### Querying by Keyword

Finally, the users query the server for the responses via PIR-by-keyword.

```go
// User 1
sk1, pk1 := keygen.GenKeyPairNew()
enc1 := bfv.NewEncryptor(params, pk1)
dec1 := bfv.NewDecryptor(params, sk1)
keypt1 := bfv.NewPlaintext(params)
encoder.Encode([]int64{12, 12, 12}, keypt1)
keyct1, _ := enc1.EncryptNew(keypt1)
eval1 := bfv.NewEvaluator(params, rlwe.NewMemEvaluationKeySet(keygen.GenRelinearizationKeyNew(sk1)))

// ...

// Server
onehotct1 := compare(eval1, negonespt, keyct1, keyspt)
resultct1, _ := eval1.MulRelinNew(onehotct1, responsespt)
// ...

// User 1
resultpt1 := dec1.DecryptNew(resultct1)
result1 := []int64{0, 0, 0}
encoder.Decode(resultpt1, result1)
res1 := result1[0] + result1[1] + result1[2]
fmt.Println("User 1 got a response", res1)

// ...
```

The server cannot tell which key each user used to query for the response.
