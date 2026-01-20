# Attestation Verifier Parsing Library

A TypeScript library for parsing and preparing attestation data for verification in Aztec smart contracts.

## Installation

```bash
npm install @your-org/att-verifier-parsing
```

## Quick Start

```typescript
import { parseAttestationData } from '@your-org/att-verifier-parsing';
import fs from 'fs';

// Load attestation data
const attestationData = JSON.parse(
  fs.readFileSync('attestation_data.json', 'utf-8')
);

// Parse it
const parsed = parseAttestationData(attestationData, {
  maxResponseNum: 2,
  allowedUrls: ['https://api.binance.com', 'https://www.okx.com'],
  grumpkinBatchSize: 253
});

// Use in smart contract
await businessProgram.methods.verify(
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
).send().wait();
```

## API

### `parseAttestationData(attestationData, config)`

Main function that parses everything you need.

**Parameters:**
- `attestationData: AttestationFile` - The attestation file data
- `config: ParseConfig`
  - `maxResponseNum: number` - Max responses allowed
  - `allowedUrls: string[]` - Allowed URL strings
  - `grumpkinBatchSize: number` - Batch size (typically 253)

**Returns:** `ParsedAttestationData` with all fields ready for verification

### Other Utilities

If you need granular control, you can import individual functions:

```typescript
import { 
  encodePacked,
  parseSignature,
  recoverPublicKey,
  parseRequestUrls,
  computeMsgsChunks,
  hashUrlsWithPoseidon2
} from '@your-org/att-verifier-parsing';
```

## Project Structure

```
att_verifier_parsing/
├── src/
│   ├── index.ts    # Main parser + exports
│   └── utils.ts    # All utilities + types
├── package.json
├── tsconfig.json
└── README.md
```

## Development

```bash
# Build
npm run build

# Use locally
npm install ../att_verifier_parsing
```

## License

MIT
