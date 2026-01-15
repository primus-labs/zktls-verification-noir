# Aztec Attestation SDK

SDK for working with Primus zkTLS attestations on Aztec.

## Installation

```bash
yarn add aztec-attestation-sdk att-verifier-parsing
```

## Usage

```typescript
import { Client, ContractHelpers } from 'aztec-attestation-sdk';
import { parseAttestationData } from 'att-verifier-parsing';

const client = new Client({
  nodeUrl: 'http://localhost:8080'
});
await client.initialize();

const alice = await client.getAccount(0);

const contract = await ContractHelpers.deployContract(
  MyContract,
  client,
  {
    admin: alice.address,
    allowedUrls: ["https://api.example.com"],
    pointH: { x: 123n, y: 456n, is_infinite: false },
    from: alice.address
  }
);

const parsed = parseAttestationData(attestationJson, config);

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
  yourPointH,
  parsed.id
).send({ from: alice.address }).wait();

if (result.status === "success" && result.blockNumber) {
  const events = await ContractHelpers.getSuccessEvents(
    client.getNode(),
    MyContract.events.SuccessEvent,
    result.blockNumber
  );
}

await client.cleanup();
```

## API

### `Client`

Basic Aztec functionality bundled for this purpose.

#### Constructor
```typescript
new Client(config: ClientConfig)
```

**Config:**
- `nodeUrl: string` - Aztec node URL
- `pxeDataDirectory?: string` - PXE data directory (default: "pxe")
- `proverEnabled?: boolean` - Enable prover (default: true)
- `cleanupBeforeInit?: boolean` - Clean old PXE data (default: true)

#### Methods

**`initialize(): Promise<void>`**
Setup PXE, wallet, and Barretenberg.

**`getAccount(index?: number): Promise<AccountWallet>`**
Get a test account by index (0-2).

**`hashUrls(urls: string[]): Promise<bigint[]>`**
Hash URLs with Poseidon2 for contract storage.

**`getNode(): AztecNode`**
Get the Aztec node client.

**`getWallet(): TestWallet`**
Get the wallet instance.

**`cleanup(): Promise<void>`**
Clean up resources.

### `ContractHelpers`

Helpers for contracts based on `contract_template`.

**`deployContract<T>(contractClass, client, params): Promise<T>`**
Deploy a template-based contract.

**`getSuccessEvents<TEvent>(node, eventType, blockNumber, maxLookback?): Promise<SuccessEvent[]>`**
Get SuccessEvent instances from a block.

## Examples

See [example/js_test/](../example/js_test/) for complete examples:
- [verify-commitment.ts](../example/js_test/verify-commitment.ts) - Commitment-based verification
- [verify-small-commitment.ts](../example/js_test/verify-small-commitment.ts) - Small commitment verification
- [verify-hash.ts](../example/js_test/verify-hash.ts) - Hash-based verification

## Building from Source

How to build & run the examples:

```bash
# 1. Build the att-verifier-parsing library
cd att_verifier_parsing
yarn && yarn build

# 2. Build the SDK
cd ../aztec-attestation-sdk
yarn && yarn build

# 3. Prep examples
cd ../example/js_test
yarn

# 4. Make sure Aztec Sandbox is running
PXE_PROVER_ENABLED=1 aztec start --sandbox

# 5. Run the examples
yarn tsx verify-commitment.ts
yarn tsx verify-small-commitment.ts
yarn tsx verify-hash.ts
```

## Requirements

- Aztec Sandbox `3.0.0-devnet.5`
- Node.js 18+
- TypeScript 5.9+
