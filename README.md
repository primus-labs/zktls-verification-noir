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

6. AttVerifier contract verify signature, check allowed urls, and decrypt the cipher text
7. AttVerifier calls BusinessProgram which includes the customized conditions and is deployed by the developers
8. BusinessProgram checks the condition and returns to AttVerifier
9. AttVerifier returns the result



## Component

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
