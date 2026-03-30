# Primus Attestations - Aztec Verifier

> Aztec version `4.2.0-aztecnr-rc.2`. 

This repo contains the necessary libraries to create an **Aztec Smart contract that verifies a Primus zkTLS attestation**. There are 2 supported types: commitment based attestation (Grumpkin curve) and hashing based attestation.

In this repo you will find the following components:
- `att_verifier_lib` - The Noir library containing the general attestation verification logic. This will be used in the smart contract.
- `att_verifier_parsing` - The TS library containing the needed parsing logic, which converts a json input into the correct values to call the Aztec smart contract.
- `aztec-attestation-sdk` - The Aztec Attestaion SDK helps you get started easily on deploying and calling your attestation contracts.
- `contract_template` - The Aztec smart contract template that can be used to complete a business case. Developers can use this as a starting point for their application.
- `example` - This contains 2 example smart contracts and a script to run end-to-end tests for these examples. 

In this README there is a [Tutorial](#tutorial-how-to-implement-your-use-case) on how to use the libraries to implement your own use case. 

## Installation and versioning

This repo uses Aztec `4.2.0-aztecnr-rc.2` with local network. Follow the documentation [here](https://docs.aztec.network/developers/getting_started_on_local_network) to install the Aztec toolchain and get started on local network. 

## Run example

Follow these steps to run the included examples:

1. Compile github_example and okx_example
```
cd example/github_example
aztec compile
aztec codegen -o src/artifacts target

cd ../okx_example
aztec compile
aztec codegen -o src/artifacts target
```

2. Move `---.ts` in `src/artifacts/` for both examples to `js_test/bindings/`. 

3. Build libraries
```
# Build parsing library
cd att_verifier_parsing
yarn && yarn build

# Build SDK
cd ../aztec-attestation-sdk
yarn && yarn build
```

4. Run the different examples:
```
aztec start --local-network
yarn tsx local-verify-github-comm.ts 
yarn tsx local-verify-github-hash.ts 
yarn tsx local-verify-okx-comm.ts 
yarn tsx local-verify-okx-hash.ts 
```

## Benchmarks

These are the benchmarks for:
- Github example, commitment-based
- Github example, hash-based
- OKX example, commitment-based
- OKX example, hash-based

The circuitsize is for the private function that does the verification. This was obtained by profiling the tx that does verification. For mode information check the Aztec docs on [profiling](https://docs.aztec.network/developers/docs/aztec-nr/framework-description/advanced/how_to_profile_transactions). 

| Method                                 | Circuitsize |
|----------------------------------------|-------------|
| GithubVerifier:verify_comm             | 279,273     |
| GithubVerifier:verify_hash             | 292,262     |
| OKXVerifier:verify_comm:               | 268,450     |
| OKXVerifier:verify_hash:               | 275,878     |

<!--### Note on zkVM Comparisons

The benchmarks and tests in this repo measure the end-to-end performance of an Aztec transaction that verifies a Primus attestation. This means we are not only measuring the proving time of the circuit, but also include things like transaction submission and communication with a local network or devnet.

Because of this, these results are not directly comparable to typical zkVM benchmarks. zkVM benchmarks usually focus on proving time in isolation and do not include blockchain-related aspects such as network interaction or state updates, so the numbers capture different kinds of costs.-->

## Tutorial: How to implement your use-case TODO update section

If you are a developer that wants to integrate an Aztec Attestation verifier in your project, you need to do the following:
1. Complete the Aztec smart contract using the `contract_template`
2. Use the SDK (`aztec-attestation-sdk`) to deploy and call the Aztec smart contract. Do this with the inputs parsed from the attestation json.

Check the `example` folder for example contracts and scripts. 

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

    BusinessProgram::at(self.address)
        .check_values_emit_event(
            self.msg_sender().unwrap(),
            self.address,
            id,
            allowed_url_matches_hashes,
            H,
        )
        .enqueue(self.context);

    true
}
```

To add the checks, you'll probably want to parse the data with the json parser that has already been added to the dependencies (`json_parser`), extract something and then do an assertion on that. See for examples of how to do this `example/real_business_program/src/main.nr` and `example/small_comm_business_program/src/main.nr`.

Note that the template contains support for both types of attestations (commitments based and hashing based), so if you're only supporting one of them, you can remove the additional code.

When the contract is complete, compile it and obtain the necessary artifacts for the script to use in step 2:
```
PXE_PROVER_ENABLED=1 aztec start --local-network
# In your contract folder
aztec-nargo compile
aztec codegen -o src/artifacts target
```

### Step 2. Deploy and call Aztec smart contract

Move `---.ts` in `src/artifacts/` and `---.json` in `target` from your smart contract into a folder that your script will be able to use. For example in `example/js_test` these files are expected to be placed in `example/js_test/bindings`. 

The following code snippets show how to use the SDK on devnet. See the full examples in `example/js_test/verify-commitment-devnet.ts` and `verify-commitment-local.ts`. This works for Aztec version `3.0.0-devnet.6-patch.1`.

// START
Initialize the client and deploy account (~2-5 minutes):
```typescript
import { Client, ContractHelpers, parseAttestationData } from "aztec-attestation-sdk";
import { BusinessProgramContract } from "./bindings/BusinessProgram.js";

const client = new Client({
  nodeUrl: "https://next.devnet.aztec-labs.com",
  mode: "devnet"
});
await client.initialize();
const alice = await client.getAccount();
```

Parse attestation data:
```typescript
const attestationData = JSON.parse(fs.readFileSync(ATT_PATH, "utf-8"));
const parsed = parseAttestationData(attestationData, {
  maxResponseNum: MAX_RESPONSE_NUM,
  allowedUrls: ALLOWED_URLS,
  grumpkinBatchSize: GRUMPKIN_BATCH_SIZE,
});

// For commitment-based attestation, set your use case's unique H point
const H = {
  x: 19978178333943292355349418156359056918133515370613875064303296301489725624535n,
  y: 13201885744872984780649110422697192888453633882501354541258277493771319153464n,
  is_infinite: false
};
```

Deploy contract (automatically hashes URLs and handles fees):
```typescript
const contract = await ContractHelpers.deployContract<BusinessProgramContract>(
  BusinessProgramContract,
  client,
  {
    admin: alice.address,
    allowedUrls: ALLOWED_URLS,
    pointH: H,
    from: alice.address,
    timeout: 1200000
  }
);
```

Verify attestation:
```typescript
const paymentMethod = client.getPaymentMethod();
const result = await contract.methods.verify_comm(
  parsed.publicKeyX,
  parsed.publicKeyY,
  parsed.hash,
  parsed.signature,
  parsed.requestUrls,
  parsed.allowedUrls,
  parsed.commitments,
  parsed.randomScalars,
  parsed.msgsChunks,
  parsed.msgs,
  H,
  parsed.id
).send({ from: alice.address, fee: { paymentMethod } }).wait({ timeout: 180000 });
```

Check for success event:
```typescript
if (result.status === "success") {
  const events = await ContractHelpers.getSuccessEvents(
    client.getNode(),
    BusinessProgramContract.events.SuccessEvent,
    result.blockNumber!
  );
  console.log("Event emitted:", events.length > 0);
}
await client.cleanup();
```

That's it! You have successfully created the Aztec Attestation verifier on devnet.

> Note: If you prefer to implement your own Aztec functionality but still want to use the parsing library for the Primus attestation JSON, use `att_verifier_parsing`. 

### Local Development

For local sandbox testing, use `mode: "local"` and remove fee payment:
```typescript
const client = new Client({ nodeUrl: "http://localhost:8080", mode: "local" });
await client.initialize();
const alice = await client.getAccount(0); // instant

// Deploy and verify without fees
const contract = await ContractHelpers.deployContract(/* same params */);
const result = await contract.methods.verify_comm(/* params */)
  .send({ from: alice.address })
  .wait();
```

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
