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
aztec codegen -o ../js_test/bindings target

cd ../okx_example
aztec compile
aztec codegen -o ../js_test/bindings target
```

2. Build libraries
```
# Build parsing library
cd att_verifier_parsing
yarn && yarn build

# Build SDK
cd ../aztec-attestation-sdk
yarn && yarn build
```

3. Run the different examples:
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

## Tutorial: How to implement your use-case

If you are a developer that wants to integrate an Aztec Attestation verifier in your project, you need to do the following steps:
1. Obtain an attestation from Primus zkTLS. 
2. Complete the Aztec smart contract using the `contract_template`.
3. Use the SDK (`aztec-attestation-sdk`) to deploy and call the Aztec smart contract. Do this with the inputs parsed from the attestation json.

Check the `example` folder for example contracts and scripts. 

### Step 1. Obtain an Attestation

To obtain an attestation use [DVC mode](https://docs.primuslabs.xyz/build/dvc) of [Primus](https://docs.primuslabs.xyz/) zkTLS. You can use their [demo code](https://github.com/primus-labs/DVC-Demo/tree/main/dvc-client/demo) as example and get started easily. 

When incorporated in the flow of your app, this gives an attestation JSON file that then can be used in the following steps.

### Step 2. Complete Aztec smart contract

In `contract_template` you'll find a full Aztec smart contract that you can use for your business case. All that needs to be added are the checks on the attested data in `verify_comm` and `verify_hash`. For example, this is the template for `verify_hash`: 

```rust
// Verify hashing-based attestation and emit event upon success
// TODO: insert here your own checks on contents
#[external("private")]
fn verify_hash(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    hash: [u8; 32],
    signature: [u8; 64],
    request_urls: [BoundedVec<u8, MAX_URL_LEN>; NUM_REQUEST_URLS],
    allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; NUM_ALLOWED_URLS],
    data_hashes: [[u8; 32]; NUM_RESPONSE_RESOLVE],
    contents: [BoundedVec<u8, MAX_PLAINTEXT_LEN>; NUM_RESPONSE_RESOLVE],
    id: Field,
) -> bool {
    let allowed_url_matches_hashes: [Field; NUM_REQUEST_URLS] = verify_attestation_hashing(
        public_key_x,
        public_key_y,
        hash,
        signature,
        request_urls,
        allowed_urls,
        data_hashes,
        contents,
    );

    // TODO insert checks on `contents`

    BusinessProgram::at(self.address)
        .check_urls_emit_event(
            self.msg_sender(),
            self.address,
            id,
            allowed_url_matches_hashes,
        )
        .enqueue(self.context);

    true
}
```

Add your custom checks after the initial verification. This can be something like a comparison or an assertion on the data. To get good performance in this function of your contract it is recommended to keep the input data as short as possible and the checks as simple as possible. To achieve that, make sure to create a very specific query for the attestation. You do this by defining the URL and then the path of where to obtain the data. The Primus docs about this are [here](https://docs.primuslabs.xyz/enterprise/multi-url/#the-usage-in-zktls-core-sdk) and you can check out our [demo](https://github.com/hashcloak/zktls_aztec_demo) with some example queries. 

Note that the contract template contains support for both types of attestations (commitments based and hashing based), so if you're only supporting one of them, you can remove the additional code.

When the contract is complete, compile it and obtain the necessary artifacts for the script to use in step 2:
```
# In your contract folder
aztec compile
aztec codegen -o ../js_test/bindings target
```

### Step 2. Deploy and call Aztec smart contract

The following code snippets show how to use the Aztec SDK on local network. See a few full examples:
- `example/js_test/local-verify-github-comm.ts`
- `example/js_test/local-verify-github-hash.ts`
- `example/js_test/local-verify-okx-comm.ts`
- `example/js_test/local-verify-okx-hash.ts`
These run on verzion `4.2.0-aztecnr-rc.2` of Aztec. 

Initialize the client and deploy account:
```typescript
import { Client } from "aztec-attestation-sdk";

const client = new Client({ nodeUrl: "http://localhost:8080" });
await client.initialize();
const account = await client.getAccount(0);
```

Parse attestation data:
```typescript
import { parseHashingData } from "aztec-attestation-sdk";

// Customize this to your use-case
const ALLOWED_URLS = ["https://api.github.com", "https://www.okx.com", "https://x.com"];
const MAX_RESPONSE_NUM = 2;

const attestationData = JSON.parse(fs.readFileSync(ATT_PATH, "utf-8"));
const parsed = parseHashingData(rawData, {
  maxResponseNum: MAX_RESPONSE_NUM,
  allowedUrls: ALLOWED_URL,
});
```

Deploy contract. 
```typescript
import { ContractHelpers } from "aztec-attestation-sdk";
import { ProgramContractContract } from "./bindings/Program.ts";

const DEPLOY_TIMEOUT = 300000; // 5 min

const contract = await ContractHelpers.deployContract(ProgramContract, client, {
  admin: account.address,
  allowedUrls: ALLOWED_URLS,
  from: account.address,
  timeout: DEPLOY_TIMEOUT,
});
```

Verify attestation:
```typescript
const TX_TIMEOUT = 120000;     // 2 min

const { receipt } = await contract.methods.verify_hash(
    parsed.publicKeyX, 
    parsed.publicKeyY, 
    parsed.hash, 
    parsed.signature,
    parsed.requestUrls, 
    parsed.allowedUrls, 
    parsed.dataHashes, 
    parsed.plainJsonResponses,
    parsed.id, 
    // add more inputs if that is what your use-case requires
).send({ from: account.address, wait: { timeout: TX_TIMEOUT } });
```

Check for success event:
```typescript
const { events } = await getPublicEvents<SuccessEvent>(
  client.getNode(), OKXVerifierContract.events.SuccessEvent, { txHash: receipt.txHash, contractAddress: contract.address }
);
if (events.length === 0) throw new Error("SuccessEvent was NOT emitted!");
```

That's it! You have successfully created the Aztec Attestation verifier.

> Note: If you prefer to implement your own Aztec functionality but still want to use the parsing library for the Primus attestation JSON, use `att_verifier_parsing` directly. 

## Implementation details

### Hash-based attestations & verification

For the hash-based approach the public data will contain a sha256 hash of each plaintext message in the private data. Each responseResolve returns its own plaintext in the private data part. There are 2 examples of what hash-based attestations look like in `example/js_test/test_data/github-contributors-attestation-hash.json` and `example/js_test/test_data/okx-attestation-hash.json`. 

With regards to performance it is still desirable to keep the plaintext message as small as possible. Even though any size message will hash to the same size output (256 bits), a longer input size to a private smart contract function is more expensive in Aztec and probably you'll need to parse the longer text prior to doing any assertions over it, which is very expensive too. So always try to query a small piece of data if possible. 

### Commitment-based attestations & verification

What happens exactly for a commitment-based verification? Per piece of plaintext that has been queried (1 per responseResolve) a list of commitments is generated of length at least 1. The public data contains the commitments. The private data contains the plaintext and the randomness used for the commitment. What has to be verified in Noir (in the circuit) is that each commitment was generated correctly. There are 2 examples of what commitment-based attestations look like in `example/js_test/test_data/github-contributors-attestation-commitment.json` and `example/js_test/test_data/okx-attestation-comm.json`. 

Let's say that a message is 500 bits. Then we split it into chunks of max 253 bits, so 2 `msgs_chunks` here. Then, for each chunk, a commitment is calculated in the zkTLS functionality and we obtain this in the public data part of the attestation. In the verification step we check for all `msgs_chunks`, commitments `coms` and randomnesses `rnds` that: `sum(msgs_chunks[i] * G + rnds[i] * H) == sum(coms[i])`. Here, `G` is the standard base point of the curve and `H` a second generator point on the curve. 

For commitment-based attestations, it is necessary to define an app-wide point `H`, which is public and should be in the contract storage. This point is used for the attestation verification. Currently, the value usend in Primus zkTLS equals [this](https://github.com/primus-labs/zktls-verification-noir/blob/main/example/js_test/local-verify-github-comm.ts#L31-L35), but in future versions of the API it will be adjustable and therefore should be part of the public storage. 

As said, per piece of plaintext that is queried (1 per responseResolve) there can be 1 or more commitments, depending on the length of the plaintext message. The longer the plaintext, the higher the amount of commitments that have to be checked in the verifier and the more expensive this becomes. This is because of the computations for the commitment check and also because a higher input size comes with higher cost.

### About `att_verifier_lib`

Function `verify_attestation_comm`: 
1. verifies signature
2. verifies `request_url` is the start of 1 of the `allowed_urls`. This is done in 2 steps:
  - (unconstrained) obtain the index of the `allowed_url` it matches with
  - verifies that `allowed_url` is indeed the start of the `request_url`
3. hashes the matched `allowed_url`. This is the output of the function
4. verifies commitments per "group". Per piece of plaintext, there is a separate set of commitments and the values to verify them. Per group we do a batched check which checks if for all i `coms[i] == msgs_chunks[i]*G + rnds[i]*H`

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
