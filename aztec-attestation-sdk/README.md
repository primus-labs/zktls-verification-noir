# Aztec Attestation SDK

A TypeScript SDK for deploying and interacting with Primus Noir attestation verifier contracts on Aztec. Supports both local network and devnet deployment.

## Features

- Unified API for local and devnet deployment
- Automatic fee payment handling for devnet
- Account deployment and management
- Contract helpers for devs who use the contract template
- Event retrieval utilities

## Installation

```bash
yarn add aztec-attestation-sdk
```

## Usage

### Devnet Mode

```typescript
import { Client, ContractHelpers } from "aztec-attestation-sdk";
import { BusinessProgramContract } from "./bindings/BusinessProgram.js";

// Initialize client for devnet mode
const client = new Client({
  nodeUrl: "https://next.devnet.aztec-labs.com",
  mode: "devnet"
});
await client.initialize();

// Deploy account on devnet (takes ~2-5 minutes)
const alice = await client.getAccount();

// Deploy contract with timeout
const contract = await ContractHelpers.deployContract<BusinessProgramContract>(
  BusinessProgramContract,
  client,
  {
    admin: alice.address,
    allowedUrls: ["https://api.example.com"],
    pointH: H, // for commitment-based
    from: alice.address,
    timeout: 1200000 // 20 minutes
  }
);

// Call contract method with fee payment
const paymentMethod = client.getPaymentMethod();
const sendOptions: any = { from: alice.address };
if (paymentMethod) {
  sendOptions.fee = { paymentMethod };
}

const result = await contract.methods.verify_comm(
  // ... params
).send(sendOptions).wait({ timeout: 180000 });

await client.cleanup();
```

### Local Network

```typescript
import { Client, ContractHelpers } from "aztec-attestation-sdk";
import { BusinessProgramContract } from "./bindings/BusinessProgram.js";

// Initialize client for local mode
const client = new Client({
  nodeUrl: "http://localhost:8080",
  mode: "local"
});
await client.initialize();

const alice = await client.getAccount(0);

// Deploy contract
const contract = await ContractHelpers.deployContract<BusinessProgramContract>(
  BusinessProgramContract,
  client,
  {
    admin: alice.address,
    allowedUrls: ["https://api.example.com"],
    pointH: H, // for commitment-based
    from: alice.address
  }
);

// Call contract method
const result = await contract.methods.verify_comm(
  // ... params
).send({ from: alice.address }).wait();

await client.cleanup();
```

## API Reference

### Client

#### Constructor

```typescript
new Client(config: ClientConfig)
```

**Required:**
- `nodeUrl: string` - Aztec node URL (`http://localhost:8080` for local, `https://next.devnet.aztec-labs.com` for devnet)
- `mode: "local" | "devnet"` - Network mode

**Optional (local only):**
- `pxeDataDirectory?: string` - PXE data directory (default: `"pxe"`)
- `proverEnabled?: boolean` - Enable proving (default: `true`)
- `cleanupBeforeInit?: boolean` - Cleanup PXE before init (default: `true`)

#### Methods

- `initialize()`: Sets up wallet and Barretenberg
- `getAccount(index?)`: Gets account (local: by index, devnet: deploys new)
- `hashUrls(urls: string[])`: Hashes URLs with Poseidon2
- `getPaymentMethod()`: Returns fee payment method (devnet only)
- `isDevnet()`: Returns true if in devnet mode
- `getNode()`: Returns Aztec node client
- `getWallet()`: Returns test wallet
- `getBarretenberg()`: Returns Barretenberg instance
- `cleanup()`: Destroys Barretenberg instance

### ContractHelpers

#### deployContract

```typescript
static async deployContract<T>(
  contractClass: any,
  client: Client,
  params: ContractDeploymentParams
): Promise<T>
```

Deploys a contract with automatic fee handling.

**Parameters:**
```typescript
interface ContractDeploymentParams {
  admin: AztecAddress;          // Admin address
  allowedUrls: string[];        // Allowed URLs
  pointH?: EmbeddedCurvePoint;  // Commitment point H (optional)
  from: AztecAddress;           // Sender address
  timeout?: number;             // Deployment timeout (optional)
}
```

#### getSuccessEvents

```typescript
static async getSuccessEvents(
  node: AztecNode,
  eventType: any,
  blockNumber: number,
  maxLookback?: number
): Promise<SuccessEvent[]>
```

Retrieves SuccessEvent instances from a block.

## Key Differences: Local vs Devnet

| Feature | Local | Devnet |
|---------|-------|--------|
| Account setup | Instant (predefined accounts) | ~2-5 minutes (deploy new) |
| Fee payment | Not required | Required (sponsored FPC) |
| Deployment timeout | Default (~2 min) | Recommended: 20 minutes |
| TX timeout | Default (~2 min) | Recommended: 3 minutes |
| PXE cleanup | Yes (configurable) | No |

## Examples

See the `example/js_test` directory for complete examples:
- `verify-commitment-local.ts`: Local sandbox example
- `verify-commitment-devnet.ts`: Devnet example

## Requirements

- Aztec version: `3.0.0-devnet.6-patch.1`
- Node.js: `18+`
- TypeScript: `5.9+`

For local development:
```bash
PXE_PROVER_ENABLED=1 aztec start --local-network
```

For devnet deployment:
- Access to `https://next.devnet.aztec-labs.com`

## Re-exported from att-verifier-parsing

The SDK also exports parsing utilities:

```typescript
import { parseAttestationData, parseHashingData, hashUrlsWithPoseidon2 } from "aztec-attestation-sdk";
```

See `att-verifier-parsing` documentation for details on these functions.
