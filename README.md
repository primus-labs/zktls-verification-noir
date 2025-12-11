# Primus Attestations - Aztec Verifier

This repo contains the necessary libraries to create an **Aztec Smart contract that verifies a Primus zkTLS attestation**. There are 2 supported types: commitment based attestation (Grumpkin curve) and hashing based attestation.

In this repo you will find the following components:
- `att_verifier_lib` - The Noir library containing the general attestation verification logic. This will be used in the smart contract. 
- `att_verifier_parsing` - The TS library containing the needed parsing logic, which converts a json input into the correct values to call the Aztec smart contract.
- `contract_template` - The Aztec smart contract template that can be used to complete a business case. Developers can use this as a starting point for their application.
- `example` - This contains 2 example smart contracts and a script to run end-to-end tests for these examples. It also benchmarks the examples. 

In this README there is a [Tutorial](#tutorial-how-to-implement-your-use-case) on how to use the libraries to implement your own use case. 

## Installation and versioning

This repo uses Aztec Sandbox version `3.0.0-devnet.5`. Follow the documentation [here](https://docs.aztec.network/developers/getting_started_on_sandbox#install-the-sandbox) to install the sandbox.

## Run example

1. Start an Aztec sandbox 
```
PXE_PROVER_ENABLED=1 aztec start --sandbox
```

2. Compile real_business_program and small_comm_business_program
```
# inside real_business_program
aztec-nargo compile
aztec-postprocess-contract
aztec codegen -o src/artifacts target

# inside small_comm_business_program
aztec-nargo compile
aztec-postprocess-contract
aztec codegen -o src/artifacts target
```

3. Move `---.ts` in `src/artifacts/` and `---.json` in `target` from both `real_business_program` and `small_comm_business_program` to `js_test/bindings/`. (Update the import path in `---.ts` for the jsons)

4. Build parsing library
```
cd att_verifier_lib
yarn build
```

5. Run script
```
cd ../example/js_test
yarn

# e2e test
yarn start
```

## Benchmarks

These are the benchmarks for 3 testcases; 2 for commitment based attestations with different numbers of commitments (1 versus 65) and one for hash based attestion.

### Timings

From MacBook Air with Apple M2 (8-core, 3.49 GHz) and 16 GB RAM:

| Method                                 | Time (ms)    |
|----------------------------------------|--------------|
| Commitment-based verification          | 41113.49     |
| Commitment-based verification (small)  | 36538.97     |
| Hash-based verification                | 42784.63     |


### Gatecounts

| Method                                 | Circuitsize    |
|----------------------------------------|--------------|
| Commitment-based verification          | 711.763     |
| Commitment-based verification (small)  | 321.513     |
| Hash-based verification                | 794.646     |

The flamegraphs for these 3 functions can be found in the `example` folder. 

## Tutorial: How to implement your use-case

If you are a developer that wants to integrate an Aztec Attestation verifier in your project, you need to do the following:
1. Complete the Aztec smart contract using the `contract_template`
2. Deploy and call the Aztec smart contract, with the inputs parsed from the attestation json. Use the `att_verifier_parsing` library for this. 

Check the `example` folder for 2 example contracts and an example script. 

### Step 1. Complete Aztec smart contract

In `contract_template` you'll find a full Aztec smart contract that you can use for your business case. All that needs to be added are the checks on the attested data in `verify_comm` and `verify_hash`. For example, this is the template for `verify_comm`: 

```rust
// Verify commitment-based attestation and emit event upon success
// TODO: insert here your own checks on msgs
#[external("private")]
fn verify_comm(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    hash: [u8; 32],
    signature: [u8; 64],
    request_urls: [BoundedVec<u8, MAX_URL_LEN>; 2],
    allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 3],
    coms: BoundedVec<EmbeddedCurvePoint, MAX_COMMS>,
    rnds: BoundedVec<Field, MAX_COMMS>,
    msgs_chunks: BoundedVec<Field, MAX_COMMS>,
    msgs: BoundedVec<u8, MAX_MSGS_LEN>,
    H: EmbeddedCurvePoint, // G is fixed, H is fixed per business case
    id: Field,
) -> bool {
    let allowed_url_matches_hashes: [Field; 2] = verify_attestation_comm(
        public_key_x,
        public_key_y,
        hash,
        signature,
        request_urls,
        allowed_urls,
        coms,
        rnds,
        msgs_chunks,
        H,
    );

    // TODO insert checks on msgs

    BusinessProgram::at(context.this_address())
        .check_values_emit_event(
            context.msg_sender().unwrap(),
            context.this_address(),
            id,
            allowed_url_matches_hashes,
            H,
        )
        .enqueue(&mut context);

    true
}
```

To add the checks, you'll probably want to parse the data with the json parser that has already been added to the dependencies (`json_parser`), extract something and then do an assertion on that. See for examples of how to do this `example/real_business_program/src/main.nr` and `example/small_comm_business_program/src/main.nr`.

Note that the template contains support for both types of attestations (commitments based and hashing based), so if you're only supporting one of them, you can remove the additional code.

When the contract is complete, compile it and obtain the necessary artifacts for the script to use in step 2:
```
PXE_PROVER_ENABLED=1 aztec start --sandbox
# In your contract folder
aztec-nargo compile
aztec-postprocess-contract
aztec codegen -o src/artifacts target
```

### Step 2. Deploy and call Aztec smart contract

Move `---.ts` in `src/artifacts/` and `---.json` in `target` from your smart contract into a folder that your script will be able to use. For example in `example/js_test` these files are expected to be placed in `example/js_test/bindings`. 

The following code snippets are from the full example in `example/js_test/index.ts`. This works for Aztec version `3.0.0-devnet.5`. 

Create a node and test wallet. 
```typescript
const node = createAztecNodeClient("http://localhost:8080");

const config = getPXEConfig();
await rm("pxe", { recursive: true, force: true });
config.dataDirectory = "pxe";
config.proverEnabled = true;
const wallet = await TestWallet.create(node, config);
const [aliceAccount] = await getInitialTestAccountsData();
let alice = await wallet.createSchnorrAccount(aliceAccount.secret, aliceAccount.salt);
```

Parse local attestation json file. Set `ATT_PATH_COMM` filepath, array of allowed urls `ALLOWED_URLS`, and values `MAX_RESPONSE_NUM` and `GRUMPKIN_BATCH_SIZE` according to usecase. 
```typescript
const attestationDataComm = JSON.parse(fs.readFileSync(ATT_PATH_COMM, "utf-8"));

const parsedComm = parseAttestationData(attestationDataComm, {
  maxResponseNum: MAX_RESPONSE_NUM,
  allowedUrls: ALLOWED_URL,
  grumpkinBatchSize: GRUMPKIN_BATCH_SIZE,
});
```

In the contract storage we store the hashes of the allowed urls, because storing the full urls is too large. 
```typescript
const hashedUrlsComm = await hashUrlsWithPoseidon2(bb, parsedComm.allowedUrls, Fr);
```

If you are using the commitment based approach, the use case will have its unique `H` which must be set in the smart contract as well. 
```typescript
let H = { 
  x: 19978178333943292355349418156359056918133515370613875064303296301489725624535n, 
  y: 13201885744872984780649110422697192888453633882501354541258277493771319153464n, 
  is_infinite: false 
};
```

Deploy the contract.
```typescript
const businessProgramComm = await BusinessProgramContract.deploy(
  wallet, 
  alice.address, 
  hashedUrlsComm, 
  H
)
  .send({ from: aliceAccount.address })
  .deployed();
```

Call the verification function for commitment-based attestation:
```typescript
let resultComm = await businessProgramComm.methods.verify_comm(
  parsedComm.publicKeyX,
  parsedComm.publicKeyY,
  parsedComm.hash,
  parsedComm.signature,
  parsedComm.requestUrls,
  parsedComm.allowedUrls,
  parsedComm.commitments,
  parsedComm.randomScalars,
  parsedComm.msgsChunks,
  parsedComm.msgs,
  H,
  parsedComm.id
).send({ from: aliceAccount.address }).wait();
```

If the verification is successful, a public event is emitted. Add a check to pick up this event:
```typescript
if (resultComm.status === "success") {
  const success_event_comm = await getDecodedPublicEvents<SuccessEvent>(
    node,
    BusinessProgramContract.events.SuccessEvent,
    resultComm.blockNumber!,
    2
  );
  console.log("Success event:", success_event_comm.length > 0 ? "OK - Event emitted" : "Not found");
} else {
  console.log("Verification failed");
}
```

That's it! You have successfully created the Aztec Attestation verifier. 

## Implementation details

### About `att_verifier_lib`

Function `verify_attestation_comm`: 
1. verifies signature
2. verifies `request_url` is the start of 1 of the `allowed_urls`. This is done in 2 steps:
  - (unconstrained) obtain the index of the `allowed_url` it matches with
  - verifies that `allowed_url` is indeed the start of the `request_url`
3. hashes the matched `allowed_url`. This is the output of the function
4. verifies commitments; for all i `coms[i] == msgs_chunks[i]*G + rnds[i]*H`

Function `verify_attestation_hashing`:
1. The same as `verify_attestation_comm`
2. The same as `verify_attestation_comm`
3. The same as `verify_attestation_comm`
4. verifies hashes; for all i `data_hashes[i] == sha256(plain_json_response_contents[i])`

### About `contract_template`

Contract storage contains:
- `admin`; the address that can update allowed_url_hashes.
- `allowed_url_hashes`; the hashes of allowed URLs. Storing complete URLs was too large for contract storage. 
- `H`; Point H used in commitment verification. This can be omitted if only hash based attestations are verified. 

The verification function are both private functions that call a public function at the end. In the public function the `allowed_url_matches_hashes` and point `H` are checked against public storage. The public function will be enqueued and executed at a later moment. That is why we only know the full verification has passed when the public event is emitted after all private & public checks have passed. 
