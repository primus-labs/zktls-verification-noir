# Primus Attestation Logic Verifier Contracts


## Workflow

Based on:
https://hackmd.io/zIFf5ChpRfGcT60e2KCRAQ?stext=1549%3A62%3A0%3A1759918279%3AuB_AXk&view=

1. Dapp request data attestation from Primus App
2. Primus runs zktls to generate attestation
3. Primus Apps return attestation
4. Dapp obtains the TLS AES session key from Primus
5. Dapp parses attestation data with primus zkTLS SDK and send a transaction to AttVerifier contract

--------------------on Aztec chain--------------------

6. AttVerifier contract verifies signature, check allowed urls, and decrypts the ciphertext
7. AttVerifier calls BusinessProgram which includes the customized conditions and is deployed by the developers
8. BusinessProgram checks the condition and returns to AttVerifier
9. AttVerifier sends a public "success" event and returns the result


## Components

### att_verifier
Main attestation verifier contract. Includes the logic for signature verification, url check and AES decryption.

### basic_business_program
An interface contract for business program. Provide the ABI for custom business program.

### real_business_program
A testing business program. This is the contract that will be deployed by the developers.

### js_test
JS scripts to deploy and interact with the contracts 

## QuickStart
1. Start an Aztec sandbox 
```
aztec start --sandbox
```
2. compile att_verifier and real_business_program
```
# inside att_verifier
aztec-nargo compile
aztec-postprocess-contract
aztec codegen -o src/artifacts target

# inside real_business_program
aztec-nargo compile
aztec-postprocess-contract
aztec codegen -o src/artifacts target
```
3. move `---.ts` in `src/artifacts/` and `---.json` in `target` from both `att_verifier` and `real_budiness_program` to `js_test/bindings/`. (Update the import path in `---.ts` for the jsons)

4. run script
```
# inside js_test
yarn
yarn start
```

## Adjust business logic

The current demo in `js_test` and specific business implementation in `real_business_program` takes `js_test/test_data/attestation_data.json` and:
- verifies it is a valid attestation (`AttVerifier`)
- checks the obtained plaintext has screen_name "primus_labs" and a followers_count larger than 1000 ( `BusinessProgram`)

### Aztec business contract

To write a different demo, create your own [Aztec contract](https://docs.aztec.network/) that implements the function
```rust
#[private]
fn verify(plaintext: BoundedVec<u8, 4096>) -> bool {
    // TODO
}
```

See `/real_business_program` for an example of how to parse the plaintext to JSON and obtain values from it. 

### Deploying and calling the contract

In the script you have to:
1. Deploy the `AttVerifier` (ultimately this could be deployed once).
2. Deploy the `BusinessProgram`, specific for your usecase.
3. Parse the data from the `attestation_json` correctly to input to the Aztec smart contract.
4. Call `attVerifierContract.methods.verify_attestation` using the contract address of step (2) as one of the inputs.

See for an example `js_test/index.ts`. Note that currently the Aztec js SDK is the only SDK available for contract interaction. 