/**
 * local-verify-okx-hash.ts
 *
 * Verify an OKX hash-based attestation on a local Aztec network.
 * Uses okx-attestation-hash.json (HASH_COMPARISON type).
 *
 * Prerequisites: `aztec start --local-network` running on port 8080.
 */

import fs from "fs";
import { parseHashingData } from "att-verifier-parsing";
import { OKXVerifierContract } from "./bindings/OKXVerifier.ts";
import { Client, ContractHelpers } from "aztec-attestation-sdk";
import { createAztecNodeClient } from "@aztec/aztec.js/node";
import { getPublicEvents } from "@aztec/aztec.js/events";

// Config

const LOCAL_NODE_URL = "http://localhost:8080";
const DEPLOY_TIMEOUT = 300000; // 5 min
const TX_TIMEOUT = 120000;     // 2 min

const MAX_RESPONSE_NUM = 2;
const ALLOWED_URL = ["https://api.github.com", "https://www.okx.com", "https://x.com"];
const ATT_PATH = "testdata/okx-attestation-hash.json";
const GRUMPKIN_BATCH_SIZE = 253;

// This is only needed because the example contract does commitment and has based in one
const H = {
  x: 19978178333943292355349418156359056918133515370613875064303296301489725624535n,
  y: 13201885744872984780649110422697192888453633882501354541258277493771319153464n,
  is_infinite: false,
};

// Main

console.log("=".repeat(70));
console.log("local verify_hash — OKX (HASH_COMPARISON)");
console.log("=".repeat(70));
console.log(`Connecting to local network at ${LOCAL_NODE_URL}`);
console.log("Make sure 'aztec start --local-network' is running!\n");

const client = new Client({ nodeUrl: LOCAL_NODE_URL });
await client.initialize();
const account = await client.getAccount(0);
console.log(`Using test account: ${account.address}`);

const rawData = JSON.parse(fs.readFileSync(ATT_PATH, "utf-8"));
const parsed = parseHashingData(rawData, {
  maxResponseNum: MAX_RESPONSE_NUM,
  allowedUrls: ALLOWED_URL,
  grumpkinBatchSize: GRUMPKIN_BATCH_SIZE,
});

console.log("\nDeploying OKXVerifier contract...");
const contract = await ContractHelpers.deployContract(OKXVerifierContract, client, {
  admin: account.address,
  allowedUrls: ALLOWED_URL,
  pointH: H,
  from: account.address,
  timeout: DEPLOY_TIMEOUT,
});
console.log("Contract deployed at:", contract.address.toString());

console.log("\nProfiling verify_hash...");
  // SchnorrAccount:entrypoint: 54,502 gates
  // private_kernel_init: 46,811 gates
  // OKXVerifier:verify_hash: 275,878 gates
  // private_kernel_inner: 101,237 gates
  // private_kernel_reset: 112,535 gates
  // private_kernel_tail: 88,998 gates
  // hiding_kernel: 38,069 gates
const profile = await contract.methods.verify_hash(
  parsed.publicKeyX, parsed.publicKeyY, parsed.hash, parsed.signature,
  parsed.requestUrls, parsed.allowedUrls, parsed.dataHashes, parsed.plainJsonResponses,
  parsed.id
).profile({ from: account.address, profileMode: "full", skipProofGeneration: true });

for (const s of profile.executionSteps) {
  console.log(`  ${s.functionName}: ${s.gateCount?.toLocaleString()} gates`);
}

console.log("\nExecuting verify_hash on-chain...");
const start = Date.now();
const { receipt } = await contract.methods.verify_hash(
  parsed.publicKeyX, parsed.publicKeyY, parsed.hash, parsed.signature,
  parsed.requestUrls, parsed.allowedUrls, parsed.dataHashes, parsed.plainJsonResponses,
  parsed.id
).send({ from: account.address, wait: { timeout: TX_TIMEOUT } });

console.log(`\nTransaction confirmed!`);
console.log(`   Status:       ${receipt.status}`);
console.log(`   Block number: ${receipt.blockNumber}`);
console.log(`   Duration:     ${((Date.now() - start) / 1000).toFixed(1)}s`);

const node = createAztecNodeClient(LOCAL_NODE_URL);
const { events } = await getPublicEvents<{ sender: unknown; contract_address: unknown; id: bigint }>(
  node, OKXVerifierContract.events.SuccessEvent, { txHash: receipt.txHash, contractAddress: contract.address }
);
if (events.length === 0) throw new Error("SuccessEvent was NOT emitted!");
console.log(`   SuccessEvent:  emitted (id=${events[0].event.id})`);

await client.cleanup();
process.exit(0);
